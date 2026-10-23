use super::constants::*;
use super::reader::Reader;

pub enum Signature {
    Rsa {
        pss: bool,
        hash: u16,
        bytes: Vec<u8>,
    },
    Ecdsa {
        hash: u16,
        r: Vec<u8>,
        s: Vec<u8>,
    },
}
pub fn parse_signature(raw: &[u8]) -> Result<Signature, String> {
    let mut r = Reader::new(raw);
    let alg = r.u16()?;
    let sig = match alg {
        TPM_ALG_RSASSA | TPM_ALG_RSAPSS => {
            let hash = r.u16()?;
            let bytes = r.sized(1024)?.to_vec();
            if bytes.is_empty() {
                return Err("empty rsa signature".to_string());
            }
            Signature::Rsa {
                pss: alg == TPM_ALG_RSAPSS,
                hash,
                bytes,
            }
        }
        TPM_ALG_ECDSA => {
            let hash = r.u16()?;
            let rr = r.sized(66)?.to_vec();
            let ss = r.sized(66)?.to_vec();
            if rr.is_empty() || ss.is_empty() {
                return Err("empty ecdsa signature".to_string());
            }
            Signature::Ecdsa { hash, r: rr, s: ss }
        }
        other => return Err(format!("unsupported signature algorithm 0x{other:04x}")),
    };
    r.finish()?;
    Ok(sig)
}
