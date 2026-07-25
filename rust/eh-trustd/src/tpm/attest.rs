use super::constants::*;
use super::reader::Reader;

pub struct Quote {
    pub pcr_digest: Vec<u8>,
    pub pcrs: Vec<u16>,
    pub clock_ms: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
    pub firmware_version: u64,
}

pub struct Attestation {
    pub nonce: Vec<u8>,
    pub quote: Quote,
}
pub fn parse_attest(raw: &[u8]) -> Result<Attestation, String> {
    let mut r = Reader::new(raw);
    if r.u32()? != TPM_GENERATED_VALUE {
        return Err("bad magic".to_string());
    }
    if r.u16()? != TPM_ST_ATTEST_QUOTE {
        return Err("attest type is not a quote".to_string());
    }
    r.sized(128)?;
    let nonce = r.sized(128)?.to_vec();
    let clock_ms = r.u64()?;
    let reset_count = r.u32()?;
    let restart_count = r.u32()?;
    let safe = r.u8()? != 0;
    let firmware_version = r.u64()?;
    let attested = &raw[r.pos..];

    let mut q = Reader::new(attested);
    let count = q.u32()?;
    if count > 16 {
        return Err("too many pcr selections".to_string());
    }
    let mut pcrs = Vec::new();
    for _ in 0..count {
        let hash = q.u16()?;
        let size = q.u8()? as usize;
        if size > 16 {
            return Err("pcr select is too large".to_string());
        }
        let mask = q.take(size)?;
        if hash == TPM_ALG_SHA256 {
            for (i, byte) in mask.iter().enumerate() {
                for bit in 0..8 {
                    if byte & (1 << bit) != 0 {
                        pcrs.push((i * 8 + bit) as u16);
                    }
                }
            }
        }
    }
    let pcr_digest = q.sized(64)?.to_vec();
    q.finish()?;
    if pcr_digest.len() != 32 {
        return Err("pcr digest is not 32 bytes".to_string());
    }
    Ok(Attestation {
        nonce,
        quote: Quote {
            pcr_digest,
            pcrs,
            clock_ms,
            reset_count,
            restart_count,
            safe,
            firmware_version,
        },
    })
}
