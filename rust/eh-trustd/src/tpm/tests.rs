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
