use ring::signature::{RsaPublicKeyComponents, UnparsedPublicKey};

use crate::tpm::{self, KeyKind, Quote, Signature};

pub fn check_ak(ak_pub: &[u8]) -> Result<Vec<u8>, String> {
    Ok(tpm::parse_public(ak_pub)?.name)
}

pub fn verify_quote(
    ak_pub: &[u8],
    attest: &[u8],
    signature: &[u8],
    ak_name: &[u8],
    nonce: &[u8],
) -> Result<Quote, String> {
    let public = tpm::parse_public(ak_pub)?;
    if ak_name != public.name {
        return Err("ak name does not match its public area".to_string());
    }
    let att = tpm::parse_attest(attest)?;
    if att.nonce != nonce {
        return Err("nonce mismatch".to_string());
    }
    let sig = tpm::parse_signature(signature)?;
    verify_signature(&public.kind, &sig, attest)?;
    Ok(att.quote)
}

fn pad(value: &[u8], size: usize) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() > size {
        return Err("invalid ecc coordinate length".to_string());
    }
    let mut out = vec![0u8; size - value.len()];
    out.extend_from_slice(value);
    Ok(out)
}

fn der_int(value: &[u8]) -> Result<Vec<u8>, String> {
    if value.is_empty() {
        return Err("empty der integer".to_string());
    }
    let mut first = 0;
    while first + 1 < value.len() && value[first] == 0 {
        first += 1;
    }
    let value = &value[first..];
    let mut out = Vec::with_capacity(value.len() + 1);
    if value[0] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(value);
    Ok(out)
}

fn der_signature(r: &[u8], s: &[u8]) -> Result<Vec<u8>, String> {
    let rr = der_int(r)?;
    let ss = der_int(s)?;
    let mut body = Vec::with_capacity(rr.len() + ss.len() + 6);
    body.push(0x02);
    body.push(rr.len() as u8);
    body.extend_from_slice(&rr);
    body.push(0x02);
    body.push(ss.len() as u8);
    body.extend_from_slice(&ss);
    let mut out = Vec::with_capacity(body.len() + 2);
    out.push(0x30);
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    Ok(out)
}

fn verify_signature(key: &KeyKind, sig: &Signature, msg: &[u8]) -> Result<(), String> {
    match (key, sig) {
        (KeyKind::Rsa { n, e }, Signature::Rsa { pss, hash, bytes }) => {
            let params = match (*pss, *hash) {
                (false, tpm::TPM_ALG_SHA256) => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                (false, tpm::TPM_ALG_SHA384) => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
                (true, tpm::TPM_ALG_SHA256) => &ring::signature::RSA_PSS_2048_8192_SHA256,
                (true, tpm::TPM_ALG_SHA384) => &ring::signature::RSA_PSS_2048_8192_SHA384,
                (_, other) => return Err(format!("unsupported hash algorithm 0x{other:04x}")),
            };
            RsaPublicKeyComponents {
                n: n.as_slice(),
                e: e.as_slice(),
            }
            .verify(params, msg, bytes)
            .map_err(|_| "rsa signature check failed".to_string())
        }
        (KeyKind::Ecc { curve, x, y }, Signature::Ecdsa { hash, r, s }) => {
            let size = match *curve {
                tpm::TPM_ECC_NIST_P256 => 32,
                tpm::TPM_ECC_NIST_P384 => 48,
                other => return Err(format!("unsupported ecc curve 0x{other:04x}")),
            };
            let mut point = Vec::with_capacity(1 + size * 2);
            point.push(0x04);
            point.extend_from_slice(&pad(x, size)?);
            point.extend_from_slice(&pad(y, size)?);
            if r.len() > size || s.len() > size {
                return Err("invalid ecdsa scalar length".to_string());
            }
            let der = der_signature(r, s)?;
            match (*curve, *hash) {
                (tpm::TPM_ECC_NIST_P256, tpm::TPM_ALG_SHA256) => UnparsedPublicKey::new(
                    &ring::signature::ECDSA_P256_SHA256_ASN1,
                    point.as_slice(),
                )
                .verify(msg, &der),
                (tpm::TPM_ECC_NIST_P384, tpm::TPM_ALG_SHA384) => UnparsedPublicKey::new(
                    &ring::signature::ECDSA_P384_SHA384_ASN1,
                    point.as_slice(),
                )
                .verify(msg, &der),
                (_, other) => return Err(format!("unsupported hash algorithm 0x{other:04x}")),
            }
            .map_err(|_| "ecdsa signature check failed".to_string())
        }
        _ => Err("signature and key types do not match".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_encodes_integers() {
        assert_eq!(der_int(&[0x01]).unwrap(), vec![0x01]);
        assert_eq!(der_int(&[0x00, 0x80]).unwrap(), vec![0x00, 0x80]);
        assert_eq!(der_int(&[0x00, 0x01]).unwrap(), vec![0x01]);
        assert!(der_int(&[]).is_err());
    }

    #[test]
    fn der_encodes_signature() {
        let out = der_signature(&[0x01], &[0x80]).unwrap();
        assert_eq!(
            out,
            vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80]
        );
    }

    #[test]
    fn pads_ecc_coordinates() {
        assert_eq!(pad(&[0x01], 4).unwrap(), vec![0x00, 0x00, 0x00, 0x01]);
        assert!(pad(&[], 4).is_err());
        assert!(pad(&[0x01; 5], 4).is_err());
    }

    #[test]
    fn random_inputs_never_panic() {
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..2000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let len = (state as usize) % 512;
            let mut data = vec![0u8; len];
            for byte in data.iter_mut() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                *byte = state as u8;
            }
            let _ = verify_quote(&data, &data, &data, &[], &data);
        }
    }
}
