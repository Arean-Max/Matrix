use sha2::{Digest, Sha256};

pub const TPM_ALG_RSA: u16 = 0x0001;
pub const TPM_ALG_AES: u16 = 0x0006;
pub const TPM_ALG_XOR: u16 = 0x000a;
pub const TPM_ALG_SHA256: u16 = 0x000b;
pub const TPM_ALG_SHA384: u16 = 0x000c;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_SM4: u16 = 0x0012;
pub const TPM_ALG_RSASSA: u16 = 0x0014;
pub const TPM_ALG_RSAES: u16 = 0x0015;
pub const TPM_ALG_RSAPSS: u16 = 0x0016;
pub const TPM_ALG_ECDSA: u16 = 0x0018;
pub const TPM_ALG_ECDH: u16 = 0x0019;
pub const TPM_ALG_ECDAA: u16 = 0x001a;
pub const TPM_ALG_SM2: u16 = 0x001b;
pub const TPM_ALG_ECSCHNORR: u16 = 0x001c;
pub const TPM_ALG_KDF1_SP800_56A: u16 = 0x0020;
pub const TPM_ALG_KDF2: u16 = 0x0021;
pub const TPM_ALG_KDF1_SP800_108: u16 = 0x0022;
pub const TPM_ALG_ECC: u16 = 0x0023;
pub const TPM_ALG_CAMELLIA: u16 = 0x0026;
pub const TPM_ECC_NIST_P256: u16 = 0x0003;
pub const TPM_ECC_NIST_P384: u16 = 0x0004;
pub const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

const ATTR_FIXED_TPM: u32 = 0x0000_0002;
const ATTR_FIXED_PARENT: u32 = 0x0000_0010;
const ATTR_SENSITIVE_DATA_ORIGIN: u32 = 0x0000_0020;
const ATTR_RESTRICTED: u32 = 0x0001_0000;
const ATTR_DECRYPT: u32 = 0x0002_0000;
const ATTR_SIGN: u32 = 0x0004_0000;

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| "length overflow".to_string())?;
        if end > self.buf.len() {
            return Err("truncated structure".to_string());
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn sized(&mut self, max: usize) -> Result<&'a [u8], String> {
        let n = self.u16()? as usize;
        if n > max {
            return Err(format!("field of {n} bytes exceeds limit"));
        }
        self.take(n)
    }

    fn finish(&self) -> Result<(), String> {
        if self.pos != self.buf.len() {
            return Err("trailing bytes".to_string());
        }
        Ok(())
    }
}

pub enum KeyKind {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Ecc { curve: u16, x: Vec<u8>, y: Vec<u8> },
}

pub struct Public {
    pub kind: KeyKind,
    pub name: Vec<u8>,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn append_u16(mut b: Vec<u8>, v: u16) -> Vec<u8> {
        b.extend_from_slice(&v.to_be_bytes());
        b
    }

    fn append_u32(mut b: Vec<u8>, v: u32) -> Vec<u8> {
        b.extend_from_slice(&v.to_be_bytes());
        b
    }

    fn append_u64(mut b: Vec<u8>, v: u64) -> Vec<u8> {
        b.extend_from_slice(&v.to_be_bytes());
        b
    }

    fn append_sized(mut b: Vec<u8>, v: &[u8]) -> Vec<u8> {
        b = append_u16(b, v.len() as u16);
        b.extend_from_slice(v);
        b
    }

    fn rsa_public_area(attrs: u32, name_alg: u16) -> Vec<u8> {
        rsa_public_area_with_scheme(attrs, name_alg, &TPM_ALG_NULL.to_be_bytes())
    }

    fn rsa_public_area_with_scheme(attrs: u32, name_alg: u16, scheme: &[u8]) -> Vec<u8> {
        let mut n = vec![0u8; 256];
        n[0] = 0xc1;
        n[255] = 0x01;
        let mut b = Vec::new();
        b = append_u16(b, TPM_ALG_RSA);
        b = append_u16(b, name_alg);
        b = append_u32(b, attrs);
        b = append_sized(b, &[]);
        b = append_u16(b, TPM_ALG_NULL);
        b.extend_from_slice(scheme);
        b = append_u16(b, 2048);
        b = append_u32(b, 0);
        append_sized(b, &n)
    }

    fn attestation(nonce: &[u8], digest: &[u8]) -> Vec<u8> {
        let name = vec![0x11u8; 34];
        let mut b = Vec::new();
        b = append_u32(b, TPM_GENERATED_VALUE);
        b = append_u16(b, TPM_ST_ATTEST_QUOTE);
        b = append_sized(b, &name);
        b = append_sized(b, nonce);
        b = append_u64(b, 4242);
        b = append_u32(b, 5);
        b = append_u32(b, 2);
        b.push(1);
        b = append_u64(b, 0x10000);
        let mut q = Vec::new();
        q = append_u32(q, 1);
        q = append_u16(q, TPM_ALG_SHA256);
        q.push(3);
        q.extend_from_slice(&[0x01, 0x00, 0x00]);
        q = append_sized(q, digest);
        b.extend_from_slice(&q);
        b
    }

    #[test]
    fn parses_rsa_public_area() {
        let area = rsa_public_area(0x0005_0072, TPM_ALG_SHA256);
        let public = parse_public(&area).expect("public area");
        assert_eq!(public.name.len(), 34);
        assert_eq!(&public.name[..2], &TPM_ALG_SHA256.to_be_bytes());
        match public.kind {
            KeyKind::Rsa { n, e } => {
                assert_eq!(n.len(), 256);
                assert_eq!(e, vec![0x01, 0x00, 0x01]);
            }
            KeyKind::Ecc { .. } => panic!("unexpected ecc key"),
        }
    }

    #[test]
    fn parses_signing_schemes() {
        let rsassa = [0x00, 0x14, 0x00, 0x0b];
        assert!(parse_public(&rsa_public_area_with_scheme(
            0x0005_0072,
            TPM_ALG_SHA256,
            &rsassa
        ))
        .is_ok());
        let pss = [0x00, 0x16, 0x00, 0x0b];
        assert!(parse_public(&rsa_public_area_with_scheme(
            0x0005_0072,
            TPM_ALG_SHA256,
            &pss
        ))
        .is_ok());
        assert!(parse_public(&rsa_public_area_with_scheme(
            0x0005_0072,
            TPM_ALG_SHA256,
            &TPM_ALG_RSAES.to_be_bytes()
        ))
        .is_err());
    }

    #[test]
    fn rejects_every_truncation() {
        let area = rsa_public_area(0x0005_0072, TPM_ALG_SHA256);
        for cut in 0..area.len() {
            assert!(parse_public(&area[..cut]).is_err());
        }
    }

    #[test]
    fn rejects_weak_attributes_and_hashes() {
        let weak = rsa_public_area(0x0004_0072, TPM_ALG_SHA256);
        assert!(parse_public(&weak).is_err());
        let sha1 = rsa_public_area(0x0005_0072, 0x0004);
        assert!(parse_public(&sha1).is_err());
        let decrypt = rsa_public_area(0x0007_0072, TPM_ALG_SHA256);
        assert!(parse_public(&decrypt).is_err());
    }

    #[test]
    fn parses_quote_attestation() {
        let nonce = vec![0x42; 32];
        let digest = vec![0x24; 32];
        let att = parse_attest(&attestation(&nonce, &digest)).expect("attestation");
        assert_eq!(att.nonce, nonce);
        assert_eq!(att.quote.pcr_digest, digest);
        assert_eq!(att.quote.pcrs, vec![0]);
        assert_eq!(att.quote.clock_ms, 4242);
        assert_eq!(att.quote.reset_count, 5);
        assert_eq!(att.quote.restart_count, 2);
        assert!(att.quote.safe);
        assert_eq!(att.quote.firmware_version, 0x10000);
    }

    #[test]
    fn rejects_attestation_truncation() {
        let att = attestation(&[0x42; 32], &[0x24; 32]);
        for cut in 0..att.len() {
            assert!(parse_attest(&att[..cut]).is_err());
        }
    }

    #[test]
    fn parses_signatures() {
        let mut rsa = Vec::new();
        rsa = append_u16(rsa, TPM_ALG_RSASSA);
        rsa = append_u16(rsa, TPM_ALG_SHA256);
        rsa = append_sized(rsa, &[0x55; 256]);
        assert!(matches!(
            parse_signature(&rsa),
            Ok(Signature::Rsa { pss: false, .. })
        ));

        let mut pss = Vec::new();
        pss = append_u16(pss, TPM_ALG_RSAPSS);
        pss = append_u16(pss, TPM_ALG_SHA256);
        pss = append_sized(pss, &[0x55; 256]);
        assert!(matches!(
            parse_signature(&pss),
            Ok(Signature::Rsa { pss: true, .. })
        ));

        let mut ecc = Vec::new();
        ecc = append_u16(ecc, TPM_ALG_ECDSA);
        ecc = append_u16(ecc, TPM_ALG_SHA256);
        ecc = append_sized(ecc, &[0x11; 32]);
        ecc = append_sized(ecc, &[0x22; 32]);
        assert!(matches!(parse_signature(&ecc), Ok(Signature::Ecdsa { .. })));

        let mut bad = Vec::new();
        bad = append_u16(bad, 0x0009);
        assert!(parse_signature(&bad).is_err());
    }
}
