//! C ABI for the client SDK.
//!
//! A handle may be used from one thread at a time; callers must synchronize
//! calls on the same handle. Returned string pointers are owned by the handle
//! and remain valid only until the next call on that handle, or until
//! `eh_client_free`. `eh_client_free` is idempotent.

use std::collections::HashSet;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use serde::Deserialize;
use serde_json::json;

use crate::client::{Activation, Client, Config};

pub const EH_OK: i32 = 0;
pub const EH_NEED_OOB: i32 = 1;
pub const EH_ERR_INVALID_ARG: i32 = -1;
pub const EH_ERR_STATE: i32 = -2;
pub const EH_ERR_NETWORK: i32 = -3;
pub const EH_ERR_SERVER: i32 = -4;
pub const EH_ERR_SESSION: i32 = -5;
pub const EH_ERR_CODE: i32 = -6;
pub const EH_ERR_PACKAGE: i32 = -7;
pub const EH_ERR_PANIC: i32 = -99;

#[derive(Deserialize)]
struct FfiConfig {
    server: String,
    license_key: String,
    data_dir: String,
    #[serde(default)]
    ca_pem_path: Option<String>,
    #[serde(default)]
    spki_pin_hex: Option<String>,
    #[serde(default)]
    package_id: Option<String>,
    #[serde(default)]
    package_file: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default = "yes")]
    use_tpm: bool,
}

fn yes() -> bool {
    true
}

fn parse_pin(hex_pin: &str) -> Result<[u8; 32], crate::Error> {
    let raw = hex::decode(hex_pin.trim())
        .map_err(|_| crate::Error::Config("spki_pin_hex is not hex".into()))?;
    if raw.len() != 32 {
        return Err(crate::Error::Config("spki_pin_hex must be 32 bytes".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn build_config(f: FfiConfig) -> Result<Config, crate::Error> {
    let mut http = crate::HttpConfig::new(f.server);
    if let Some(path) = f.ca_pem_path {
        http.ca_pem = Some(
            std::fs::read(&path)
                .map_err(|e| crate::Error::Config(format!("cannot read CA {path}: {e}")))?,
        );
    }
    if let Some(pin) = f.spki_pin_hex {
        http.spki_pin = Some(parse_pin(&pin)?);
    }
    let mut cfg = Config::new(
        "https://placeholder.invalid",
        &f.license_key,
        PathBuf::from(f.data_dir),
    );
    cfg.http = http;
    cfg.fingerprint_override = f.fingerprint;
    cfg.package_id = f.package_id;
    cfg.package_file = f.package_file.map(PathBuf::from);
    cfg.use_tpm = f.use_tpm;
    Ok(cfg)
}

pub struct EhClient {
    inner: Client,
    last_error: CString,
    status: CString,
    vm_seed: CString,
}

impl EhClient {
    fn new(inner: Client) -> EhClient {
        let mut c = EhClient {
            inner,
            last_error: CString::default(),
            status: CString::default(),
            vm_seed: CString::default(),
        };
        c.refresh();
        c
    }

    fn refresh(&mut self) {
        self.status = CString::new(self.status_json()).unwrap_or_default();
        self.vm_seed = match self.inner.session() {
            Some(s) => CString::new(hex::encode(s.vm_seed())).unwrap_or_default(),
            None => CString::default(),
        };
    }

    fn status_json(&self) -> String {
        let session = self.inner.session();
        json!({
            "version": crate::VERSION,
            "fingerprint": self.inner.fingerprint(),
            "has_session": session.is_some(),
            "session_id": session.map(|s| s.id.clone()),
            "trust": session.map(|s| s.trust.clone()),
            "lease_exp": session.map(|s| s.lease_exp),
            "offline_grace_s": session.map(|s| s.offline_grace_s),
            "heartbeat_interval_s": session.map(|s| s.heartbeat_interval_s),
            "usable_until": session.map(|s| s.usable_until()),
            "usable_offline": self.inner.usable_offline(),
            "package": session.and_then(|s| s.package()).map(|p| json!({
                "id": p.id,
                "sha256": p.sha256,
            })),
            "payload_len": self.inner.payload().map(|p| p.len()),
            "notes": self.inner.notes(),
        })
        .to_string()
    }

    fn fail(&mut self, e: &crate::Error) -> i32 {
        self.last_error = CString::new(e.to_string()).unwrap_or_default();
        self.refresh();
        match e {
            crate::Error::Config(_) => EH_ERR_INVALID_ARG,
            crate::Error::Transport(_) => EH_ERR_NETWORK,
            crate::Error::State(_) => EH_ERR_STATE,
            crate::Error::Package(_) => EH_ERR_PACKAGE,
            crate::Error::SessionLost(_) => EH_ERR_SESSION,
            crate::Error::InvalidCode { .. } | crate::Error::CodeLocked { .. } => EH_ERR_CODE,
            crate::Error::NeedOob { .. } => EH_NEED_OOB,
            _ => EH_ERR_SERVER,
        }
    }
}

fn live() -> &'static Mutex<HashSet<usize>> {
    static LIVE: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
    LIVE.get_or_init(|| Mutex::new(HashSet::new()))
}

fn is_live(client: *mut EhClient) -> bool {
    live()
        .lock()
        .map(|set| set.contains(&(client as usize)))
        .unwrap_or(false)
}

fn guard(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(EH_ERR_PANIC)
}

/// # Safety
/// The caller must pass a handle returned by `eh_client_new` and must not call
/// it concurrently with `eh_client_free` or another mutating call.
unsafe fn with<F: FnOnce(&mut EhClient) -> i32>(client: *mut EhClient, f: F) -> i32 {
    if client.is_null() || !is_live(client) {
        return EH_ERR_INVALID_ARG;
    }
    guard(|| f(&mut *client))
}

#[no_mangle]
pub unsafe extern "C" fn eh_client_new(config_json: *const c_char) -> *mut EhClient {
    if config_json.is_null() {
        return std::ptr::null_mut();
    }
    let parsed = catch_unwind(AssertUnwindSafe(|| -> Result<EhClient, String> {
        let text = CStr::from_ptr(config_json)
            .to_str()
            .map_err(|_| "config is not UTF-8".to_string())?;
        let ffi: FfiConfig = serde_json::from_str(text).map_err(|e| format!("config JSON: {e}"))?;
        let inner = Client::new(build_config(ffi).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        Ok(EhClient::new(inner))
    }));
    match parsed {
        Ok(Ok(c)) => {
            let ptr = Box::into_raw(Box::new(c));
            if let Ok(mut set) = live().lock() {
                set.insert(ptr as usize);
            }
            ptr
        }
        Ok(Err(msg)) => {
            eprintln!("eh-client: eh_client_new failed: {msg}");
            std::ptr::null_mut()
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
/// `client` must be a handle returned by `eh_client_new`. Freeing the same
/// handle more than once is a no-op after the first call.
#[no_mangle]
pub unsafe extern "C" fn eh_client_free(client: *mut EhClient) {
    if client.is_null() {
        return;
    }
    let removed = live()
        .lock()
        .map(|mut set| set.remove(&(client as usize)))
        .unwrap_or(false);
    if removed {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(client))));
    }
}

#[no_mangle]
pub unsafe extern "C" fn eh_client_activate(client: *mut EhClient, oob_code: *const c_char) -> i32 {
    with(client, |c| {
        let code = if oob_code.is_null() {
            None
        } else {
            match CStr::from_ptr(oob_code).to_str() {
                Ok(s) => Some(s),
                Err(_) => return c.fail(&crate::Error::Config("code is not UTF-8".into())),
            }
        };
        match c.inner.activate(code) {
            Ok(Activation::Ready) => {
                c.last_error = CString::default();
                c.refresh();
                EH_OK
            }
            Ok(Activation::NeedOob { .. }) => {
                c.refresh();
                EH_NEED_OOB
            }
            Err(e) => c.fail(&e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn eh_client_establish(client: *mut EhClient) -> i32 {
    with(client, |c| match c.inner.establish() {
        Ok(()) => {
            c.last_error = CString::default();
            c.refresh();
            EH_OK
        }
        Err(e) => c.fail(&e),
    })
}

#[no_mangle]
pub unsafe extern "C" fn eh_client_heartbeat(client: *mut EhClient) -> i32 {
    with(client, |c| match c.inner.heartbeat() {
        Ok(()) => {
            c.last_error = CString::default();
            c.refresh();
            EH_OK
        }
        Err(e) => c.fail(&e),
    })
}

#[no_mangle]
pub unsafe extern "C" fn eh_client_ensure_session(client: *mut EhClient) -> i32 {
    with(client, |c| match c.inner.ensure_session() {
        Ok(()) => {
            c.last_error = CString::default();
            c.refresh();
            EH_OK
        }
        Err(e) => c.fail(&e),
    })
}

#[no_mangle]
pub unsafe extern "C" fn eh_client_status_json(client: *mut EhClient) -> *const c_char {
    if client.is_null() || !is_live(client) {
        return std::ptr::null();
    }
    guard_ref(|| {
        let c = &mut *client;
        c.refresh();
        c.status.as_ptr()
    })
}

#[no_mangle]
pub unsafe extern "C" fn eh_client_last_error(client: *mut EhClient) -> *const c_char {
    if client.is_null() || !is_live(client) {
        return std::ptr::null();
    }
    guard_ref(|| (&*client).last_error.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn eh_client_vm_seed(client: *mut EhClient) -> *const c_char {
    if client.is_null() || !is_live(client) {
        return std::ptr::null();
    }
    guard_ref(|| {
        let c = &mut *client;
        c.refresh();
        c.vm_seed.as_ptr()
    })
}

#[no_mangle]
pub unsafe extern "C" fn eh_client_payload(
    client: *mut EhClient,
    out_len: *mut usize,
) -> *const u8 {
    if client.is_null() || !is_live(client) {
        return std::ptr::null();
    }
    guard_ref(|| {
        let c = &*client;
        match c.inner.payload() {
            Some(p) => {
                if !out_len.is_null() {
                    *out_len = p.len();
                }
                p.as_ptr()
            }
            None => std::ptr::null(),
        }
    })
}

fn guard_ref<T>(f: impl FnOnce() -> *const T) -> *const T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(std::ptr::null())
}

#[cfg(all(windows, test))]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_with_bad_config() {
        let bad = CString::new("not json").unwrap();
        let null_cfg = unsafe { eh_client_new(std::ptr::null()) };
        assert!(null_cfg.is_null());
        let c = unsafe { eh_client_new(bad.as_ptr()) };
        assert!(c.is_null());

        let cfg = CString::new(
            json!({
                "server": "https://127.0.0.1:1",
                "license_key": "EH1-TEST",
                "data_dir": std::env::temp_dir().join("eh-ffi-test").to_string_lossy(),
                "fingerprint": "ab".repeat(32),
                "use_tpm": false,
            })
            .to_string(),
        )
        .unwrap();
        let client = unsafe { eh_client_new(cfg.as_ptr()) };
        assert!(!client.is_null());

        let status = unsafe { CStr::from_ptr(eh_client_status_json(client)) }
            .to_str()
            .unwrap()
            .to_string();
        assert!(status.contains("has_session"));

        let rc = unsafe { eh_client_heartbeat(std::ptr::null_mut()) };
        assert_eq!(rc, EH_ERR_INVALID_ARG);
        let rc = unsafe { eh_client_ensure_session(client) };
        assert!(rc < 0 && rc != EH_ERR_PANIC);
        let msg = unsafe { CStr::from_ptr(eh_client_last_error(client)) }
            .to_str()
            .unwrap()
            .to_string();
        assert!(!msg.is_empty());

        unsafe { eh_client_free(client) };
        assert!(unsafe { eh_client_status_json(client) }.is_null());
        unsafe { eh_client_free(client) };
        unsafe { eh_client_free(std::ptr::null_mut()) };
    }
}
