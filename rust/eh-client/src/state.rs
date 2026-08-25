use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::dpapi;
use crate::error::{Error, Result};

const STATE_FILE: &str = "client.state";
const STATE_VERSION: u32 = 1;
const LOCK_STALE_AFTER: Duration = Duration::from_secs(30);

struct StateLock {
    path: PathBuf,
}

impl StateLock {
    fn acquire(dir: &Path) -> Result<StateLock> {
        let path = dir.join(format!("{STATE_FILE}.lock"));
        for _ in 0..100 {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut f) => {
                    let _ = writeln!(f, "{}", std::process::id());
                    let _ = f.sync_all();
                    return Ok(StateLock { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if let Ok(meta) = std::fs::metadata(&path) {
                        if let Ok(modified) = meta.modified() {
                            if modified
                                .elapsed()
                                .map(|age| age > LOCK_STALE_AFTER)
                                .unwrap_or(false)
                            {
                                let _ = std::fs::remove_file(&path);
                                continue;
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => {
                    return Err(Error::State(format!("lock {}: {e}", path.display())));
                }
            }
        }
        Err(Error::State(format!(
            "timed out waiting for {}",
            path.display()
        )))
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SavedPackage {
    pub id: String,
    pub sha256: String,
    pub key_hex: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SavedSession {
    pub session_id: String,
    pub pop_seed_hex: String,
    pub kem_secret_hex: String,
    pub lease_exp: i64,
    pub heartbeat_interval_s: i64,
    pub offline_grace_s: i64,
    pub ack: String,
    pub seq: u64,
    pub trust: String,
    pub vm_seed: String,
    pub package: Option<SavedPackage>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SavedState {
    pub version: u32,
    pub fingerprint: String,
    pub session: Option<SavedSession>,
}

impl SavedState {
    pub fn load(dir: &Path) -> Result<SavedState> {
        let path = dir.join(STATE_FILE);
        if !path.exists() {
            return Ok(SavedState {
                version: STATE_VERSION,
                ..Default::default()
            });
        }
        let sealed = std::fs::read(&path)
            .map_err(|e| Error::State(format!("read {}: {e}", path.display())))?;
        let plain = dpapi::unprotect(&sealed)?;
        let state: SavedState = serde_json::from_slice(&plain)
            .map_err(|e| Error::State(format!("parse {}: {e}", path.display())))?;
        if state.version != STATE_VERSION {
            return Err(Error::State(format!(
                "state version {} is not supported",
                state.version
            )));
        }
        Ok(state)
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::State(format!("create {}: {e}", dir.display())))?;
        let _lock = StateLock::acquire(dir)?;
        let plain = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::State(format!("encode state: {e}")))?;
        let sealed = dpapi::protect(&plain)?;
        let path = dir.join(STATE_FILE);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp: PathBuf = dir.join(format!("{STATE_FILE}.tmp.{}.{}", std::process::id(), nanos));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| Error::State(format!("write {}: {e}", tmp.display())))?;
        if let Err(e) = f.write_all(&sealed).and_then(|_| f.sync_all()) {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::State(format!("write {}: {e}", tmp.display())));
        }
        drop(f);
        if let Err(e) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::State(format!("replace {}: {e}", path.display())));
        }
        Ok(())
    }

    pub fn clear_session(&mut self) {
        self.session = None;
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_replace() {
        let dir = std::env::temp_dir().join(format!("eh-state-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut st = SavedState {
            version: STATE_VERSION,
            fingerprint: "ab".repeat(32),
            session: Some(SavedSession {
                session_id: "s1".into(),
                pop_seed_hex: "00".repeat(32),
                kem_secret_hex: "01".repeat(32),
                lease_exp: 42,
                heartbeat_interval_s: 900,
                offline_grace_s: 100,
                ack: "aa".repeat(32),
                seq: 3,
                trust: "tpm-attested".into(),
                vm_seed: "bb".repeat(32),
                package: None,
            }),
        };
        st.save(&dir).unwrap();

        let loaded = SavedState::load(&dir).unwrap();
        assert_eq!(loaded.fingerprint, "ab".repeat(32));
        assert_eq!(loaded.session.as_ref().unwrap().seq, 3);

        st.clear_session();
        st.save(&dir).unwrap();
        assert!(SavedState::load(&dir).unwrap().session.is_none());

        std::fs::write(dir.join(STATE_FILE), b"garbage").unwrap();
        assert!(SavedState::load(&dir).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
