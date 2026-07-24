use sha2::{Digest, Sha256};

use super::constants::*;
use super::reader::Reader;

pub enum KeyKind {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Ecc { curve: u16, x: Vec<u8>, y: Vec<u8> },
}

pub struct Public {
    pub kind: KeyKind,
    pub name: Vec<u8>,
}
fn parse_symmetric(r: &mut Reader<'_>) -> Result<(), String> {
    match r.u16()? {
        TPM_ALG_NULL => Ok(()),
        TPM_ALG_AES | TPM_ALG_SM4 | TPM_ALG_CAMELLIA | TPM_ALG_XOR => {
            r.u16()?;
            r.u16()?;
            Ok(())
        }
        alg => Err(format!("unsupported symmetric algorithm 0x{alg:04x}")),
    }
}

fn parse_scheme(r: &mut Reader<'_>) -> Result<u16, String> {
    let alg = r.u16()?;
    match alg {
        TPM_ALG_NULL | TPM_ALG_RSAES => {}
        TPM_ALG_RSASSA | TPM_ALG_RSAPSS | TPM_ALG_ECDSA | TPM_ALG_SM2 | TPM_ALG_ECSCHNORR => {
            r.u16()?;
        }
        TPM_ALG_ECDH => {
            parse_kdf(r)?;
        }
        TPM_ALG_ECDAA => {
            r.u16()?;
            r.u16()?;
        }
        other => return Err(format!("unsupported scheme 0x{other:04x}")),
    }
    Ok(alg)
}

fn parse_kdf(r: &mut Reader<'_>) -> Result<(), String> {
    match r.u16()? {
        TPM_ALG_NULL => Ok(()),
        TPM_ALG_KDF1_SP800_56A | TPM_ALG_KDF2 | TPM_ALG_KDF1_SP800_108 => {
            r.u16()?;
            Ok(())
        }
        alg => Err(format!("unsupported kdf 0x{alg:04x}")),
    }
}

fn parse_rsa(r: &mut Reader<'_>) -> Result<KeyKind, String> {
    parse_symmetric(r)?;
    let scheme = parse_scheme(r)?;
    if !matches!(scheme, TPM_ALG_NULL | TPM_ALG_RSASSA | TPM_ALG_RSAPSS) {
        return Err("rsa ak has a non-signing scheme".to_string());
    }
    let bits = r.u16()? as usize;
    let exponent = r.u32()?;
    let n = r.sized(1024)?.to_vec();
    if n.len() < 256 {
        return Err("rsa modulus is smaller than 2048 bits".to_string());
    }
    if bits != n.len() * 8 {
        return Err("rsa key bits do not match the modulus".to_string());
    }
    let e = if exponent == 0 {
        vec![0x01, 0x00, 0x01]
    } else {
        let raw = exponent.to_be_bytes();
        let first = raw.iter().position(|b| *b != 0).unwrap_or(raw.len());
        raw[first..].to_vec()
    };
    Ok(KeyKind::Rsa { n, e })
}

fn parse_ecc(r: &mut Reader<'_>) -> Result<KeyKind, String> {
    parse_symmetric(r)?;
    let scheme = parse_scheme(r)?;
    if !matches!(scheme, TPM_ALG_NULL | TPM_ALG_ECDSA) {
        return Err("ecc ak has a non-signing scheme".to_string());
    }
    let curve = r.u16()?;
    parse_kdf(r)?;
    let x = r.sized(66)?.to_vec();
    let y = r.sized(66)?.to_vec();
    let size = match curve {
        TPM_ECC_NIST_P256 => 32,
        TPM_ECC_NIST_P384 => 48,
        other => return Err(format!("unsupported ecc curve 0x{other:04x}")),
    };
    if x.is_empty() || y.is_empty() || x.len() > size || y.len() > size {
        return Err("invalid ecc point coordinates".to_string());
    }
    Ok(KeyKind::Ecc { curve, x, y })
}

pub fn parse_public(raw: &[u8]) -> Result<Public, String> {
    if raw.is_empty() || raw.len() > 2048 {
        return Err("invalid ak public area size".to_string());
    }
    let mut r = Reader::new(raw);
    let kind_alg = r.u16()?;
    let name_alg = r.u16()?;
    if name_alg != TPM_ALG_SHA256 {
        return Err("ak nameAlg is not sha256".to_string());
    }
    let attrs = r.u32()?;
    r.sized(64)?;
    let kind = match kind_alg {
        TPM_ALG_RSA => parse_rsa(&mut r)?,
        TPM_ALG_ECC => parse_ecc(&mut r)?,
        other => return Err(format!("ak type 0x{other:04x} is not RSA or ECC")),
    };
    r.finish()?;
    let required = ATTR_FIXED_TPM
        | ATTR_FIXED_PARENT
        | ATTR_SENSITIVE_DATA_ORIGIN
        | ATTR_RESTRICTED
        | ATTR_SIGN;
    if attrs & required != required {
        return Err(
            "ak lacks restricted/sign/fixedTPM/fixedParent/sensitiveDataOrigin".to_string(),
        );
    }
    if attrs & ATTR_DECRYPT != 0 {
        return Err("ak is a decryption key".to_string());
    }
    let mut name = Vec::with_capacity(34);
    name.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    name.extend_from_slice(&Sha256::digest(raw));
    Ok(Public { kind, name })
}
