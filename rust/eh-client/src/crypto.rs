use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::error::{Error, Result};

const XNONCE: usize = 24;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

pub fn hkdf32(ikm: &[u8], salt: &[u8], info: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm)
        .expect("32 bytes is a valid HKDF output");
    okm
}

pub fn heartbeat_sign_bytes(session_id: &str, seq: u64, prev_ack: &str) -> Vec<u8> {
    format!("EH-HB1|{session_id}|{seq}|{prev_ack}").into_bytes()
}

pub fn activation_proof(secret: &[u8], nonce_hex: &str) -> String {
    hex::encode(hmac_sha256(
        secret,
        format!("EH-ACT1|{nonce_hex}").as_bytes(),
    ))
}

pub struct SessionKeys {
    pub pop_signing: SigningKey,
    pub pop_public: VerifyingKey,
    pub kem_secret: StaticSecret,
    pub kem_public: X25519Public,
}

impl SessionKeys {
    pub fn generate() -> SessionKeys {
        let pop_signing = SigningKey::generate(&mut OsRng);
        let pop_public = pop_signing.verifying_key();
        let kem_secret = StaticSecret::random_from_rng(OsRng);
        let kem_public = X25519Public::from(&kem_secret);
        SessionKeys {
            pop_signing,
            pop_public,
            kem_secret,
            kem_public,
        }
    }

    pub fn sign_heartbeat(&self, session_id: &str, seq: u64, prev_ack: &str) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let msg = heartbeat_sign_bytes(session_id, seq, prev_ack);
        self.pop_signing.sign(&msg).to_bytes().to_vec()
    }

    pub fn open_package_key(
        &self,
        server_public: &[u8],
        session_id: &str,
        package_id: &str,
        wrapped: &[u8],
    ) -> Result<[u8; 32]> {
        if server_public.len() != 32 {
            return Err(Error::Protocol("server kem key is not 32 bytes".into()));
        }
        if wrapped.len() <= XNONCE {
            return Err(Error::Package("wrapped key too short".into()));
        }
        let mut server = [0u8; 32];
        server.copy_from_slice(server_public);
        let shared = self.kem_secret.diffie_hellman(&X25519Public::from(server));
        let k = hkdf32(shared.as_bytes(), session_id.as_bytes(), "eh/pkg-wrap/v1");

        let cipher = XChaCha20Poly1305::new((&k).into());
        let nonce = XNonce::from_slice(&wrapped[..XNONCE]);
        let plain = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &wrapped[XNONCE..],
                    aad: package_id.as_bytes(),
                },
            )
            .map_err(|_| Error::Package("package key failed to unwrap".into()))?;
        if plain.len() != 32 {
            return Err(Error::Package("package key is not 32 bytes".into()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&plain);
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_matches_manual() {
        let got = hkdf32(&[1u8; 32], &[2u8; 4], "eh/field/v1");
        let hk = Hkdf::<Sha256>::new(Some(&[2u8; 4]), &[1u8; 32]);
        let mut want = [0u8; 32];
        hk.expand(b"eh/field/v1", &mut want).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn package_key_round_trip() {
        use chacha20poly1305::aead::Aead;
        let keys = SessionKeys::generate();
        let session_id = "00112233445566778899aabbccddeeff";
        let package_id = "demo-core";
        let key = [42u8; 32];

        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = X25519Public::from(&server_secret);
        let shared = server_secret.diffie_hellman(&keys.kem_public);
        let k = hkdf32(shared.as_bytes(), session_id.as_bytes(), "eh/pkg-wrap/v1");
        let cipher = XChaCha20Poly1305::new((&k).into());
        let nonce = [7u8; XNONCE];
        let mut wrapped = nonce.to_vec();
        wrapped.extend_from_slice(
            &cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &key,
                        aad: package_id.as_bytes(),
                    },
                )
                .unwrap(),
        );

        let opened = keys
            .open_package_key(server_public.as_bytes(), session_id, package_id, &wrapped)
            .unwrap();
        assert_eq!(opened, key);

        assert!(keys
            .open_package_key(server_public.as_bytes(), session_id, "other", &wrapped)
            .is_err());
    }

    #[test]
    fn heartbeat_signature_verifies() {
        use ed25519_dalek::Verifier;
        let keys = SessionKeys::generate();
        let sig = keys.sign_heartbeat("sid", 7, "ack");
        let msg = heartbeat_sign_bytes("sid", 7, "ack");
        let parsed = ed25519_dalek::Signature::from_slice(&sig).unwrap();
        assert!(keys.pop_public.verify(&msg, &parsed).is_ok());
    }
}
