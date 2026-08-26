use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::{Error, Result};

pub const MAGIC: &[u8] = b"EHPKG1\n";
pub const VERSION: u32 = 1;
const MAX_HEADER: usize = 8 << 10;
const MAX_CONTAINER: usize = 512 << 20;
const NONCE: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub version: u32,
    pub id: String,
    pub name: String,
    pub sha256: String,
    pub created_at: i64,
    pub builder: String,
}

pub fn valid_package_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-' || c == b'_'
        })
}

pub fn inspect(container: &[u8]) -> Result<(Header, &[u8])> {
    if container.len() > MAX_CONTAINER {
        return Err(Error::Package("container too large".into()));
    }
    let rest = container
        .strip_prefix(MAGIC)
        .ok_or_else(|| Error::Package("not an EHPKG1 container".into()))?;
    let nl = rest
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| Error::Package("header not terminated".into()))?;
    if nl > MAX_HEADER {
        return Err(Error::Package("header too large".into()));
    }
    let header: Header =
        serde_json::from_slice(&rest[..nl]).map_err(|e| Error::Package(format!("header: {e}")))?;
    if header.version != VERSION {
        return Err(Error::Package(format!(
            "unsupported container version {}",
            header.version
        )));
    }
    if !valid_package_id(&header.id) || !is_hex(&header.sha256, 32) {
        return Err(Error::Package("bad header fields".into()));
    }
    Ok((header, &rest[nl + 1..]))
}

pub fn open(container: &[u8], key: &[u8; 32]) -> Result<(Header, Vec<u8>)> {
    let (header, sealed) = inspect(container)?;
    if sealed.len() <= NONCE {
        return Err(Error::Package("truncated payload".into()));
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let payload = cipher
        .decrypt(
            XNonce::from_slice(&sealed[..NONCE]),
            Payload {
                msg: &sealed[NONCE..],
                aad: header.id.as_bytes(),
            },
        )
        .map_err(|_| Error::Package("decryption failed".into()))?;
    if crypto::sha256_hex(&payload) != header.sha256 {
        return Err(Error::Package("payload hash mismatch".into()));
    }
    Ok((header, payload))
}

fn is_hex(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2
        && s.bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::Aead;

    fn seal(id: &str, payload: &[u8], key: &[u8; 32]) -> Vec<u8> {
        let header = Header {
            version: VERSION,
            id: id.into(),
            name: "test".into(),
            sha256: crypto::sha256_hex(payload),
            created_at: 1,
            builder: "test".into(),
        };
        let hj = serde_json::to_vec(&header).unwrap();
        let cipher = XChaCha20Poly1305::new(key.into());
        let nonce = [9u8; NONCE];
        let sealed = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: payload,
                    aad: id.as_bytes(),
                },
            )
            .unwrap();
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&hj);
        out.push(b'\n');
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        out
    }

    #[test]
    fn open_round_trip() {
        let key = [7u8; 32];
        let container = seal("demo-core", b"payload bytes", &key);
        let (hdr, payload) = open(&container, &key).unwrap();
        assert_eq!(hdr.id, "demo-core");
        assert_eq!(payload, b"payload bytes");
    }

    #[test]
    fn wrong_key_and_relabel_rejected() {
        let key = [7u8; 32];
        let container = seal("demo-core", b"payload", &key);
        assert!(open(&container, &[8u8; 32]).is_err());

        let other = seal("other-pkg", b"payload", &key);
        let (hdr, sealed) = inspect(&other).unwrap();
        let mut relabeled = MAGIC.to_vec();
        relabeled.extend_from_slice(
            &serde_json::to_vec(&Header {
                id: "demo-core".into(),
                ..hdr
            })
            .unwrap(),
        );
        relabeled.push(b'\n');
        relabeled.extend_from_slice(sealed);
        assert!(open(&relabeled, &key).is_err());
    }

    #[test]
    fn tampered_payload_rejected() {
        let key = [1u8; 32];
        let mut container = seal("demo-core", b"payload", &key);
        let n = container.len();
        container[n - 1] ^= 0x01;
        assert!(open(&container, &key).is_err());
    }

    #[test]
    fn garbage_rejected() {
        assert!(open(b"EHPKG1\nnot json\nxx", &[0u8; 32]).is_err());
        assert!(open(b"NOTPKG", &[0u8; 32]).is_err());
        assert!(valid_package_id("demo-core_1.0"));
        assert!(!valid_package_id("Demo"));
        assert!(!valid_package_id(""));
    }
}
