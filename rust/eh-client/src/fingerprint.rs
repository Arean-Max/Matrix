#[cfg(windows)]
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
pub fn machine_fingerprint() -> Result<String> {
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW;
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNamePhysicalDnsHostname, GetComputerNameExW,
    };

    let mut guid = String::new();
    let sub = wide("SOFTWARE\\Microsoft\\Cryptography");
    let val = wide("MachineGuid");
    let mut buf = vec![0u16; 512];
    let mut size = (buf.len() * 2) as u32;

    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            sub.as_ptr(),
            val.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if rc == 0 {
        let chars = (size as usize / 2).saturating_sub(1);
        guid = String::from_utf16_lossy(&buf[..chars]);
    }

    let mut name_buf = vec![0u16; 256];
    let mut name_len = name_buf.len() as u32;
    let mut host = String::new();

    if unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            name_buf.as_mut_ptr(),
            &mut name_len,
        )
    } != 0
    {
        host = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    }

    let mut serial: u32 = 0;
    let root = wide("C:\\");

    let vol_ok = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    } != 0;

    if guid.is_empty() && host.is_empty() && !vol_ok {
        return Err(Error::Config(
            "cannot read any fingerprint source (MachineGuid, hostname, volume serial)".into(),
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(b"EH-FP1|");
    hasher.update(guid.as_bytes());
    hasher.update(b"|");
    hasher.update(host.as_bytes());
    hasher.update(b"|");
    hasher.update(format!("{serial:08x}").as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(not(windows))]
pub fn machine_fingerprint() -> Result<String> {
    Err(Error::Config(
        "machine fingerprints are only defined on Windows".into(),
    ))
}

pub fn validate_fingerprint(fp: &str) -> Result<String> {
    let fp = fp.trim().to_ascii_lowercase();
    let ok = fp.len() == 64 && fp.bytes().all(|c| c.is_ascii_hexdigit());
    if !ok {
        return Err(Error::Config(
            "fingerprint must be exactly 64 lowercase hex characters".into(),
        ));
    }
    Ok(fp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn fingerprint_is_stable_and_hex() {
        let a = machine_fingerprint().unwrap();
        let b = machine_fingerprint().unwrap();
        assert_eq!(a, b);
        assert!(validate_fingerprint(&a).is_ok());
    }

    #[test]
    fn override_validation() {
        assert!(validate_fingerprint(&"ab".repeat(32)).is_ok());
        assert!(validate_fingerprint(&"AB".repeat(32)).is_ok());
        assert!(validate_fingerprint("abc").is_err());
        assert!(validate_fingerprint(&"zz".repeat(32)).is_err());
    }
}
