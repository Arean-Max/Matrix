use crate::error::{Error, Result};

const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
const ENTROPY: &[u8] = b"eh-client/state/v1";

#[cfg(windows)]
fn blob(bytes: &[u8]) -> windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
    windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    }
}

#[cfg(windows)]
pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};

    let data_in = blob(plaintext);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &data_in,
            std::ptr::null(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(Error::State("DPAPI encryption failed".into()));
    }

    let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
    unsafe { LocalFree(out.pbData.cast()) };
    Ok(bytes)
}

#[cfg(windows)]
pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

    let data_in = blob(ciphertext);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &data_in,
            std::ptr::null_mut(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(Error::State(
            "cannot decrypt state (different user or corrupted file)".into(),
        ));
    }

    let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
    unsafe { LocalFree(out.pbData.cast()) };
    Ok(bytes)
}

#[cfg(not(windows))]
pub fn protect(_plaintext: &[u8]) -> Result<Vec<u8>> {
    Err(Error::State("DPAPI is Windows-only".into()))
}

#[cfg(not(windows))]
pub fn unprotect(_ciphertext: &[u8]) -> Result<Vec<u8>> {
    Err(Error::State("DPAPI is Windows-only".into()))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let secret = b"session state payload";
        let sealed = protect(secret).unwrap();
        assert_ne!(sealed, secret);
        assert_eq!(unprotect(&sealed).unwrap(), secret);
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(unprotect(b"not a dpapi blob").is_err());
    }
}
