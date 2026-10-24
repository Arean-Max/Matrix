use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::de::DeserializeOwned;
use serde::Serialize;
use ureq::Agent;

use crate::crypto::sha256;
use crate::error::{Error, Result};
use crate::wire::{self, ErrorBody};

#[derive(Clone)]
pub struct HttpConfig {
    pub base: String,
    /// Custom CA bundle. When set, it replaces the public webpki roots; add
    /// any public roots you still need to this bundle.
    pub ca_pem: Option<Vec<u8>>,
    pub spki_pin: Option<[u8; 32]>,
    pub timeout: Duration,
}

impl HttpConfig {
    pub fn new(base: impl Into<String>) -> HttpConfig {
        HttpConfig {
            base: base.into(),
            ca_pem: None,
            spki_pin: None,
            timeout: Duration::from_secs(30),
        }
    }
}

pub struct Http {
    agent: Agent,
    base: String,
}

impl Http {
    pub fn new(cfg: &HttpConfig) -> Result<Http> {
        let base = cfg.base.trim_end_matches('/').to_string();
        if !base.starts_with("https://") {
            return Err(Error::Config(format!(
                "server must be an https:// URL, got {base:?}"
            )));
        }
        let tls = Arc::new(build_client_config(cfg)?);
        let agent = ureq::AgentBuilder::new()
            .tls_connector(Arc::new(tls))
            .redirects(0)
            .https_only(true)
            .timeout(cfg.timeout)
            .user_agent(concat!("eh-client/", env!("CARGO_PKG_VERSION")))
            .build();
        Ok(Http { agent, base })
    }

    pub fn post_json<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        let url = format!("{}{}", self.base, path);
        let payload =
            serde_json::to_vec(body).map_err(|e| Error::Config(format!("encode request: {e}")))?;
        let response = match self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .set(wire::PROTOCOL_HEADER, wire::PROTOCOL_VERSION)
            .send_bytes(&payload)
        {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(ureq::Error::Transport(t)) => {
                return Err(Error::Transport(t.to_string()));
            }
        };

        let status = response.status();
        let mut raw = Vec::new();
        response
            .into_reader()
            .take(1 << 20)
            .read_to_end(&mut raw)
            .map_err(|e| Error::Transport(e.to_string()))?;

        if !(200..300).contains(&status) {
            return Err(decode_error(status, &raw));
        }
        serde_json::from_slice::<R>(&raw)
            .map_err(|e| Error::Protocol(format!("decode response: {e}")))
    }
}

use std::io::Read as _;

fn decode_error(status: u16, raw: &[u8]) -> Error {
    let parsed = serde_json::from_slice::<ErrorBody>(raw).ok();
    let Some(body) = parsed else {
        return Error::Api {
            status,
            code: "bad_response".into(),
            message: "non-JSON error body".into(),
            retry_after_s: 0,
        };
    };
    let e = body.error;
    match e.code.as_str() {
        wire::CODE_OOB_REQUIRED => Error::NeedOob { expires_at: 0 },
        wire::CODE_INVALID_CODE => Error::InvalidCode {
            attempts_remaining: e
                .details
                .as_ref()
                .and_then(|d| d.get("attempts_remaining"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
        },
        wire::CODE_CODE_LOCKED => Error::CodeLocked {
            retry_after_s: e.retry_after_s,
        },
        wire::CODE_SESSION_REVOKED
        | wire::CODE_UNKNOWN_SESSION
        | wire::CODE_LEASE_EXPIRED
        | wire::CODE_ACK_CHAIN_BROKEN => Error::SessionLost(e.code),
        _ => Error::Api {
            status,
            code: e.code,
            message: e.message,
            retry_after_s: e.retry_after_s,
        },
    }
}

fn parse_pem_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let text =
        std::str::from_utf8(pem).map_err(|_| Error::Config("CA file is not utf-8 PEM".into()))?;
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after = &rest[start + 27..];
        let Some(end) = after.find("-----END CERTIFICATE-----") else {
            return Err(Error::Config("unterminated PEM certificate".into()));
        };
        let body: String = after[..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        use base64::Engine as _;
        let der = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|e| Error::Config(format!("CA file: bad base64: {e}")))?;
        out.push(CertificateDer::from(der));
        rest = &after[end..];
    }
    if out.is_empty() {
        return Err(Error::Config("CA file contains no certificates".into()));
    }
    Ok(out)
}

fn build_client_config(cfg: &HttpConfig) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    if let Some(pem) = &cfg.ca_pem {
        for cert in parse_pem_certs(pem)? {
            roots
                .add(cert)
                .map_err(|e| Error::Config(format!("CA file: {e}")))?;
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| Error::Config(format!("tls verifier: {e}")))?;

    let verifier: Arc<dyn ServerCertVerifier> = match cfg.spki_pin {
        Some(pin) => Arc::new(PinningVerifier { inner, pin }),
        None => inner,
    };

    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .map_err(|e| Error::Config(format!("tls setup: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(config)
}

struct PinningVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pin: [u8; 32],
}

impl std::fmt::Debug for PinningVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinningVerifier")
            .field("pin", &hex::encode(self.pin))
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let spki = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|_| rustls::Error::General("pin: cannot parse certificate".into()))?
            .subject_public_key_info();
        let got = sha256(spki.as_ref());
        if got != self.pin {
            return Err(rustls::Error::General(
                "server certificate does not match the pinned key".into(),
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_parser_reads_certificates() {
        let der_a = [0x30, 0x03, 0x02, 0x01, 0x01];
        let der_b = [0x30, 0x03, 0x02, 0x01, 0x02];
        use base64::Engine as _;
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(der_a),
            base64::engine::general_purpose::STANDARD.encode(der_b),
        );
        let certs = parse_pem_certs(pem.as_bytes()).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].as_ref(), der_a);
        assert_eq!(certs[1].as_ref(), der_b);
        assert!(parse_pem_certs(b"no pem here").is_err());
    }

    #[test]
    fn rejects_plain_http() {
        let cfg = HttpConfig::new("http://license.example.com");
        assert!(Http::new(&cfg).is_err());
    }

    #[test]
    fn non_json_error_is_not_attestation_failure() {
        match decode_error(502, b"<html>bad gateway</html>") {
            Error::Api { code, message, .. } => {
                assert_eq!(code, "bad_response");
                assert!(message.contains("bad gateway"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn ack_chain_broken_loses_the_session() {
        let body = br#"{"error":{"code":"ack_chain_broken","message":"stale ack"}}"#;
        match decode_error(409, body) {
            Error::SessionLost(code) => assert_eq!(code, "ack_chain_broken"),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
