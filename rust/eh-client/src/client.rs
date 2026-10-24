use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::crypto::SessionKeys;
use crate::error::{Error, Result};
use crate::fingerprint;
use crate::http::{Http, HttpConfig};
use crate::packaging;
use crate::state::{SavedPackage, SavedSession, SavedState};
use crate::wire;

#[derive(Clone)]
pub struct Config {
    pub http: HttpConfig,
    pub license_key: String,
    pub data_dir: PathBuf,
    pub fingerprint_override: Option<String>,
    pub package_id: Option<String>,
    pub package_file: Option<PathBuf>,
    pub use_tpm: bool,
}

impl Config {
    pub fn new(server: &str, license_key: &str, data_dir: PathBuf) -> Config {
        Config {
            http: HttpConfig::new(server),
            license_key: license_key.to_string(),
            data_dir,
            fingerprint_override: None,
            package_id: None,
            package_file: None,
            use_tpm: true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Activation {
    Ready,
    NeedOob { expires_at: i64 },
}

pub struct Session {
    pub id: String,
    pub trust: String,
    pub lease_exp: i64,
    pub offline_grace_s: i64,
    pub heartbeat_interval_s: i64,
    keys: SessionKeys,
    ack: String,
    seq: u64,
    vm_seed: [u8; 32],
    package: Option<SavedPackage>,
}

impl Session {
    pub fn usable_until(&self) -> i64 {
        self.lease_exp + self.offline_grace_s
    }

    pub fn vm_seed(&self) -> &[u8; 32] {
        &self.vm_seed
    }

    pub fn package(&self) -> Option<&SavedPackage> {
        self.package.as_ref()
    }
}

pub struct Client {
    cfg: Config,
    http: Http,
    fingerprint: String,
    state: SavedState,
    session: Option<Session>,
    payload: Option<Vec<u8>>,
    notes: Vec<String>,
}

impl Client {
    pub fn new(cfg: Config) -> Result<Client> {
        if cfg.license_key.trim().is_empty() {
            return Err(Error::Config("license key is empty".into()));
        }
        let http = Http::new(&cfg.http)?;
        let fingerprint = match &cfg.fingerprint_override {
            Some(fp) => fingerprint::validate_fingerprint(fp)?,
            None => fingerprint::machine_fingerprint()?,
        };
        let mut state = SavedState::load(&cfg.data_dir)?;
        if state.fingerprint != fingerprint {
            state.clear_session();
        }
        state.fingerprint = fingerprint.clone();

        let mut client = Client {
            cfg,
            http,
            fingerprint,
            state,
            session: None,
            payload: None,
            notes: Vec::new(),
        };
        client.restore_session()?;
        Ok(client)
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    fn note(&mut self, msg: impl Into<String>) {
        self.notes.push(msg.into());
    }

    pub fn usable_offline(&self) -> bool {
        match &self.session {
            Some(s) => now() <= s.usable_until(),
            None => false,
        }
    }

    pub fn activate(&mut self, code: Option<&str>) -> Result<Activation> {
        let resp: wire::ActivateResponse = self.http.post_json(
            "/api/v1/activate",
            &wire::ActivateRequest {
                license_key: &self.cfg.license_key,
                fingerprint: &self.fingerprint,
            },
        )?;
        match resp.status.as_str() {
            wire::STATUS_READY => Ok(Activation::Ready),
            wire::STATUS_OOB_REQUIRED => {
                let Some(code) = code else {
                    return Ok(Activation::NeedOob {
                        expires_at: resp.oob_expires_at,
                    });
                };
                let code = code.trim();
                if code.len() != 8 || !code.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Error::Config(
                        "the out-of-band code is exactly 8 digits".into(),
                    ));
                }
                let v: wire::VerifyOobResponse = self.http.post_json(
                    "/api/v1/verify-oob",
                    &wire::VerifyOobRequest {
                        license_key: &self.cfg.license_key,
                        fingerprint: &self.fingerprint,
                        code,
                    },
                )?;
                if v.status == wire::STATUS_READY {
                    Ok(Activation::Ready)
                } else {
                    Err(Error::Protocol(format!(
                        "unexpected verify-oob status {:?}",
                        v.status
                    )))
                }
            }
            other => Err(Error::Protocol(format!(
                "unexpected activate status {other:?}"
            ))),
        }
    }

    pub fn establish(&mut self) -> Result<()> {
        let mut bundle: Option<attest::Bundle> = None;
        #[cfg(windows)]
        if self.cfg.use_tpm {
            match attest::Bundle::open() {
                Ok(b) => bundle = Some(b),
                Err(e) => self.note(format!("TPM unavailable, continuing unattested: {e}")),
            }
        }

        let mut plan = if bundle.is_some() {
            Plan::Full
        } else {
            Plan::Bare
        };

        loop {
            match self.establish_attempt(plan, bundle.as_mut())? {
                Attempt::Done => return Ok(()),
                Attempt::Downgrade(reason) => {
                    self.note(reason);
                    plan = match plan {
                        Plan::Full => Plan::NoActivation,
                        Plan::NoActivation | Plan::Bare => {
                            return Err(Error::Protocol(
                                "all attestation attempts were rejected".into(),
                            ))
                        }
                    };
                }
            }
        }
    }

    fn establish_attempt(
        &mut self,
        plan: Plan,
        mut bundle: Option<&mut attest::Bundle>,
    ) -> Result<Attempt> {
        let ek_info = match (plan, &bundle) {
            (Plan::Full, Some(b)) => Some(b.ek_info()),
            _ => None,
        };
        let challenge: wire::ChallengeResponse = self.http.post_json(
            "/api/v1/challenge",
            &wire::ChallengeRequest {
                license_key: &self.cfg.license_key,
                fingerprint: &self.fingerprint,
                ek: ek_info.as_ref(),
            },
        )?;

        let mut activation_hmac = String::new();
        if let Some(blob) = &challenge.activation {
            let Some(b) = bundle.as_deref_mut() else {
                return Err(Error::Protocol(
                    "server issued an activation blob but no TPM is available".into(),
                ));
            };
            match b.activation_proof(blob, &challenge.nonce) {
                Ok(proof) => activation_hmac = proof,
                Err(Error::ActivationBlocked) => {
                    return Ok(Attempt::Downgrade(
                        "ActivateCredential blocked (run elevated for tpm-attested); \
                         retrying with a quote-only challenge"
                            .into(),
                    ));
                }
                Err(e) => return Err(e),
            }
        }

        let nonce_bytes = hex::decode(&challenge.nonce)
            .map_err(|_| Error::Protocol("challenge nonce is not hex".into()))?;
        let quote = match (plan, &bundle) {
            (Plan::Full | Plan::NoActivation, Some(b)) => match b.quote(&nonce_bytes) {
                Ok(q) => Some(q),
                Err(e) => {
                    self.note(format!("quote failed ({e}); verifying without one"));
                    None
                }
            },
            _ => None,
        };

        let package_id = self.cfg.package_id.clone().unwrap_or_default();
        let keys = SessionKeys::generate();
        let req = wire::VerifyRequest {
            license_key: &self.cfg.license_key,
            fingerprint: &self.fingerprint,
            nonce: &challenge.nonce,
            pop_pub: b64(&keys.pop_public.to_bytes()),
            kem_pub: b64(keys.kem_public.as_bytes()),
            package_id: &package_id,
            activation_hmac: activation_hmac.clone(),
            quote: quote.clone(),
        };
        let resp: wire::VerifyResponse = match self.http.post_json("/api/v1/verify", &req) {
            Ok(r) => r,
            Err(e) if plan != Plan::Bare && is_attestation_error(&e) => {
                return Ok(Attempt::Downgrade(format!(
                    "server rejected the {plan:?} attestation ({e}); retrying weaker"
                )));
            }
            Err(e) => return Err(e),
        };

        if resp.status != wire::STATUS_ACTIVE {
            return Err(Error::Protocol(format!(
                "unexpected verify status {:?}",
                resp.status
            )));
        }
        if let Some(wanted) = &self.cfg.package_id {
            match &resp.package {
                Some(pkg) if &pkg.id == wanted => {}
                Some(pkg) => {
                    return Err(Error::Package(format!(
                        "server delivered package {:?}, requested {:?}",
                        pkg.id, wanted
                    )))
                }
                None => {
                    return Err(Error::Package(format!(
                        "server did not return the requested package {wanted:?}"
                    )))
                }
            }
        }

        self.payload = None;
        self.session = Some(Session {
            id: resp.session_id.clone(),
            trust: resp.trust.clone(),
            lease_exp: resp.lease_exp,
            offline_grace_s: resp.offline_grace_s,
            heartbeat_interval_s: resp.heartbeat_interval_s,
            keys,
            ack: resp.ack.clone(),
            seq: 0,
            vm_seed: hex32(&resp.vm_seed)?,
            package: None,
        });

        if let Some(pkg) = &resp.package {
            if let Err(e) = self.receive_package(pkg) {
                self.session = None;
                self.payload = None;
                return Err(e);
            }
        }

        self.persist()?;
        Ok(Attempt::Done)
    }

    fn receive_package(&mut self, pkg: &wire::WrappedPackage) -> Result<()> {
        if let Some(wanted) = &self.cfg.package_id {
            if &pkg.id != wanted {
                return Err(Error::Package(format!(
                    "server delivered package {:?}, requested {:?}",
                    pkg.id, wanted
                )));
            }
        }
        let (key, record) = {
            let session = self
                .session
                .as_mut()
                .ok_or_else(|| Error::Protocol("package without a session".into()))?;
            let wrapped = b64d(&pkg.wrapped_key)?;
            let server_kem = b64d(&pkg.kem_pub)?;
            let key = session
                .keys
                .open_package_key(&server_kem, &session.id, &pkg.id, &wrapped)?;
            let record = SavedPackage {
                id: pkg.id.clone(),
                sha256: pkg.sha256.clone(),
                key_hex: hex::encode(key),
            };
            (key, record)
        };

        let Some(path) = &self.cfg.package_file else {
            if let Some(session) = self.session.as_mut() {
                session.package = Some(record);
            }
            self.note(format!(
                "no package_file configured; package {:?} key unwrapped but payload not opened",
                pkg.id
            ));
            return Ok(());
        };
        let container = std::fs::read(path)
            .map_err(|e| Error::Package(format!("read {}: {e}", path.display())))?;
        let (header, payload) = packaging::open(&container, &key)?;
        if header.id != pkg.id {
            return Err(Error::Package(format!(
                "container id {:?} is not the delivered package {:?}",
                header.id, pkg.id
            )));
        }
        if !header.sha256.eq_ignore_ascii_case(&pkg.sha256) {
            return Err(Error::Package(
                "container payload hash differs from the server's record".into(),
            ));
        }
        if let Some(session) = self.session.as_mut() {
            session.package = Some(record);
        }
        self.note(format!(
            "package {:?} opened: {} bytes",
            pkg.id,
            payload.len()
        ));
        self.payload = Some(payload);
        Ok(())
    }

    pub fn heartbeat(&mut self) -> Result<()> {
        let Some(session) = self.session.as_mut() else {
            return Err(Error::SessionLost("no session".into()));
        };
        let seq = session.seq + 1;
        let prev_ack = session.ack.clone();
        let sig = session.keys.sign_heartbeat(&session.id, seq, &prev_ack);
        let req = wire::HeartbeatRequest {
            session_id: &session.id,
            seq,
            prev_ack: &prev_ack,
            pop_sig: b64(&sig),
            client_time_ms: now() * 1000,
        };
        let resp: wire::HeartbeatResponse = match self.http.post_json("/api/v1/heartbeat", &req) {
            Ok(r) => r,
            Err(e @ Error::SessionLost(_)) => {
                self.drop_session();
                return Err(e);
            }
            Err(e) => return Err(e),
        };

        let session = self.session.as_mut().expect("session survived");
        session.seq = seq;
        session.ack = resp.ack;
        session.lease_exp = resp.lease_exp;
        session.heartbeat_interval_s = resp.next_interval_s;
        self.persist()
    }

    pub fn ensure_session(&mut self) -> Result<()> {
        if self.session.is_none() {
            return self.establish();
        }
        match self.heartbeat() {
            Ok(()) => Ok(()),
            Err(e @ Error::SessionLost(_)) => {
                self.note(format!("{e}; establishing a new session"));
                self.establish()
            }
            Err(e) => Err(e),
        }
    }

    fn restore_session(&mut self) -> Result<()> {
        let Some(saved) = self.state.session.clone() else {
            return Ok(());
        };

        if let Some(wanted) = self.cfg.package_id.clone() {
            let saved_pkg = saved.package.as_ref().map(|p| p.id.clone());
            if saved_pkg.as_deref() != Some(wanted.as_str()) {
                match &saved_pkg {
                    Some(id) => self.note(format!(
                        "saved session carries package {id:?}; establishing a new \
                         session for {wanted:?}"
                    )),
                    None => self.note(format!(
                        "saved session has no package; establishing a new session \
                         for {wanted:?}"
                    )),
                }
                self.state.clear_session();
                self.state.save(&self.cfg.data_dir)?;
                return Ok(());
            }
        }
        let session = session_from_saved(saved)?;
        if now() > session.usable_until() {
            self.state.clear_session();
            self.state.save(&self.cfg.data_dir)?;
            return Ok(());
        }
        self.session = Some(session);
        self.restore_payload();
        Ok(())
    }

    fn restore_payload(&mut self) {
        let Some(pkg) = self.session.as_ref().and_then(|s| s.package.clone()) else {
            return;
        };
        let Some(path) = self.cfg.package_file.clone() else {
            self.note(format!(
                "package {:?} is known; no package_file configured to open it",
                pkg.id
            ));
            return;
        };
        let opened = (|| -> Result<(packaging::Header, Vec<u8>)> {
            let key = hex32(&pkg.key_hex)?;
            let container = std::fs::read(&path)
                .map_err(|e| Error::Package(format!("read {}: {e}", path.display())))?;

            let (head, _) = packaging::inspect(&container)?;
            if head.id != pkg.id {
                return Err(Error::Package(format!(
                    "container {:?} is not the saved package {:?}",
                    head.id, pkg.id
                )));
            }
            let (header, payload) = packaging::open(&container, &key)?;
            if !header.sha256.eq_ignore_ascii_case(&pkg.sha256) {
                return Err(Error::Package(
                    "container payload hash differs from the saved record".into(),
                ));
            }
            Ok((header, payload))
        })();
        match opened {
            Ok((_, payload)) => {
                self.note(format!(
                    "package {:?} reopened: {} bytes",
                    pkg.id,
                    payload.len()
                ));
                self.payload = Some(payload);
            }
            Err(e) => self.note(format!("saved package could not be reopened: {e}")),
        }
    }

    fn drop_session(&mut self) {
        self.session = None;
        self.payload = None;
        self.state.clear_session();
        if let Err(e) = self.state.save(&self.cfg.data_dir) {
            self.note(format!("could not update the state file: {e}"));
        }
    }

    fn persist(&mut self) -> Result<()> {
        let Some(session) = &self.session else {
            return Ok(());
        };
        self.state.session = Some(SavedSession {
            session_id: session.id.clone(),
            pop_seed_hex: hex::encode(session.keys.pop_signing.to_bytes()),
            kem_secret_hex: hex::encode(session.keys.kem_secret.to_bytes()),
            lease_exp: session.lease_exp,
            heartbeat_interval_s: session.heartbeat_interval_s,
            offline_grace_s: session.offline_grace_s,
            ack: session.ack.clone(),
            seq: session.seq,
            trust: session.trust.clone(),
            vm_seed: hex::encode(session.vm_seed),
            package: session.package.clone(),
        });
        self.state.save(&self.cfg.data_dir)
    }

    pub fn package_key_hex(&self) -> Option<String> {
        self.session
            .as_ref()
            .and_then(|s| s.package.as_ref())
            .map(|p| p.key_hex.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Plan {
    Full,
    NoActivation,
    Bare,
}

enum Attempt {
    Done,
    Downgrade(String),
}

fn is_attestation_error(e: &Error) -> bool {
    matches!(
        e,
        Error::Api { code, .. }
            if code == wire::CODE_ATTESTATION_FAILED
                || code == wire::CODE_ACTIVATION_FAILED
                || code == wire::CODE_INVALID_NONCE
    )
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64d(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| Error::Protocol("malformed base64 from server".into()))
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(s).map_err(|_| Error::Protocol(format!("not hex: {s:?}")))?;
    if raw.len() != 32 {
        return Err(Error::Protocol(format!(
            "want 32 bytes of hex, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn session_from_saved(saved: SavedSession) -> Result<Session> {
    let seed = hex32(&saved.pop_seed_hex)?;
    let kem = hex32(&saved.kem_secret_hex)?;
    let pop_signing = SigningKey::from_bytes(&seed);
    let pop_public = pop_signing.verifying_key();
    let kem_secret = StaticSecret::from(kem);
    let kem_public = X25519Public::from(&kem_secret);
    Ok(Session {
        id: saved.session_id,
        trust: saved.trust,
        lease_exp: saved.lease_exp,
        offline_grace_s: saved.offline_grace_s,
        heartbeat_interval_s: saved.heartbeat_interval_s,
        keys: SessionKeys {
            pop_signing,
            pop_public,
            kem_secret,
            kem_public,
        },
        ack: saved.ack,
        seq: saved.seq,
        vm_seed: hex32(&saved.vm_seed)?,
        package: saved.package,
    })
}

#[cfg(windows)]
mod attest {
    use super::{b64, b64d, Result};
    use crate::crypto;
    use crate::tpm::{LoadedKey, Tpm, DEFAULT_QUOTED_PCRS};
    use crate::wire;

    pub struct Bundle {
        tpm: Tpm,
        ek: LoadedKey,
        ak: LoadedKey,
    }

    impl Bundle {
        pub fn open() -> Result<Bundle> {
            let tpm = Tpm::open()?;
            let ek = tpm.create_ek()?;
            let ak = match tpm.create_ak() {
                Ok(ak) => ak,
                Err(e) => {
                    tpm.flush(ek.handle);
                    return Err(e);
                }
            };
            Ok(Bundle { tpm, ek, ak })
        }

        pub fn ek_info(&self) -> wire::EkInfo {
            wire::EkInfo {
                ek_hash: self.ek.ek_hash_hex(),
                ek_pub: b64(&self.ek.public),
                ak_pub: b64(&self.ak.public),
                ak_name: self.ak.name_hex.clone(),
            }
        }

        pub fn activation_proof(
            &self,
            blob: &wire::ActivationBlob,
            nonce_hex: &str,
        ) -> Result<String> {
            let id_object = b64d(&blob.id_object)?;
            let enc_secret = b64d(&blob.enc_secret)?;
            let secret =
                self.tpm
                    .activate_credential(&self.ak, &self.ek, &id_object, &enc_secret)?;
            Ok(crypto::activation_proof(&secret, nonce_hex))
        }

        pub fn quote(&self, nonce_bytes: &[u8]) -> Result<wire::QuoteInfo> {
            let (attest, signature) =
                self.tpm
                    .quote(&self.ak, nonce_bytes, &DEFAULT_QUOTED_PCRS)?;
            Ok(wire::QuoteInfo {
                attest: b64(&attest),
                signature: b64(&signature),
                ak_pub: b64(&self.ak.public),
                ak_name: self.ak.name_hex.clone(),
                ek_hash: self.ek.ek_hash_hex(),
            })
        }
    }

    impl Drop for Bundle {
        fn drop(&mut self) {
            self.tpm.flush(self.ak.handle);
            self.tpm.flush(self.ek.handle);
        }
    }
}

#[cfg(not(windows))]
mod attest {
    pub struct Bundle;
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    fn seal(id: &str, payload: &[u8], key: &[u8; 32]) -> Vec<u8> {
        let header = packaging::Header {
            version: packaging::VERSION,
            id: id.into(),
            name: "test".into(),
            sha256: crate::crypto::sha256_hex(payload),
            created_at: 1,
            builder: "test".into(),
        };
        let hj = serde_json::to_vec(&header).unwrap();
        let cipher = XChaCha20Poly1305::new(key.into());
        let nonce = [9u8; 24];
        let sealed = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: payload,
                    aad: id.as_bytes(),
                },
            )
            .unwrap();
        let mut out = packaging::MAGIC.to_vec();
        out.extend_from_slice(&hj);
        out.push(b'\n');
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        out
    }

    fn saved_state(fp: &str, pkg_id: &str, key: &[u8; 32], sha: &str) -> SavedState {
        SavedState {
            version: 1,
            fingerprint: fp.into(),
            session: Some(SavedSession {
                session_id: "s1".into(),
                pop_seed_hex: "00".repeat(32),
                kem_secret_hex: "01".repeat(32),
                lease_exp: now() + 3600,
                heartbeat_interval_s: 900,
                offline_grace_s: 100,
                ack: "aa".repeat(32),
                seq: 1,
                trust: "ek-bound".into(),
                vm_seed: "bb".repeat(32),
                package: Some(SavedPackage {
                    id: pkg_id.into(),
                    sha256: sha.into(),
                    key_hex: hex::encode(key),
                }),
            }),
        }
    }

    fn cfg(dir: &std::path::Path, fp: &str, pkg: Option<(&str, &std::path::Path)>) -> Config {
        let mut cfg = Config::new("https://127.0.0.1:9", "EH1-TEST", dir.to_path_buf());
        cfg.fingerprint_override = Some(fp.into());
        if let Some((id, file)) = pkg {
            cfg.package_id = Some(id.into());
            cfg.package_file = Some(file.to_path_buf());
        }
        cfg
    }

    #[test]
    fn restore_session_follows_the_requested_package() {
        let base = std::env::temp_dir().join(format!("eh-client-restore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let fp = "ab".repeat(32);

        let old_key = [7u8; 32];
        let old_payload = b"old payload";
        let old_container = base.join("old.ehpkg");
        std::fs::write(&old_container, seal("oldpkg", old_payload, &old_key)).unwrap();
        let state = saved_state(
            &fp,
            "oldpkg",
            &old_key,
            &crate::crypto::sha256_hex(old_payload),
        );
        state.save(&base).unwrap();

        let client = Client::new(cfg(&base, &fp, Some(("newpkg", &old_container)))).unwrap();
        assert!(client.session().is_none(), "session must not be adopted");
        assert!(client
            .notes()
            .iter()
            .any(|n| n.contains("establishing a new session")));
        assert!(SavedState::load(&base).unwrap().session.is_none());

        state.save(&base).unwrap();
        let client = Client::new(cfg(&base, &fp, Some(("oldpkg", &old_container)))).unwrap();
        assert!(client.session().is_some());
        assert_eq!(client.payload().unwrap(), old_payload);

        state.save(&base).unwrap();
        let client = Client::new(cfg(&base, &fp, None)).unwrap();
        assert!(client.session().is_some());

        state.save(&base).unwrap();
        let other = base.join("other.ehpkg");
        std::fs::write(&other, seal("other", b"x", &[9u8; 32])).unwrap();
        let client = Client::new(cfg(&base, &fp, Some(("oldpkg", &other)))).unwrap();
        assert!(client.session().is_some());
        assert!(client.payload().is_none());
        assert!(client
            .notes()
            .iter()
            .any(|n| n.contains("is not the saved package")));

        let _ = std::fs::remove_dir_all(&base);
    }
}
