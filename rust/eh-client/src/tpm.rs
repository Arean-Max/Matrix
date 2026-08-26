use std::ffi::c_void;

use windows_sys::Win32::System::TpmBaseServices::{
    Tbsi_Context_Create, Tbsip_Context_Close, Tbsip_Submit_Command, TBS_CONTEXT_PARAMS,
    TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0, TBS_CONTEXT_VERSION_TWO,
};

use crate::error::{Error, Result};

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_CFB: u16 = 0x0043;
const TPM_ALG_RSASSA: u16 = 0x0014;
const TPM_RH_ENDORSEMENT: u32 = 0x4000000B;
const TPM_RS_PW: u32 = 0x40000009;
const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM_CC_QUOTE: u32 = 0x0000_0158;
const TPM_CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const ATTR_FIXED_TPM: u32 = 0x0000_0002;
const ATTR_FIXED_PARENT: u32 = 0x0000_0010;
const ATTR_SENSITIVE_DATA_ORIGIN: u32 = 0x0000_0020;
const ATTR_USER_WITH_AUTH: u32 = 0x0000_0040;
const ATTR_NO_DA: u32 = 0x0000_0400;
const ATTR_RESTRICTED: u32 = 0x0001_0000;
const ATTR_DECRYPT: u32 = 0x0002_0000;
const ATTR_SIGN: u32 = 0x0004_0000;
const TBS_COMMAND_BLOCKED: u32 = 0x8028_0400;
pub const DEFAULT_QUOTED_PCRS: [u32; 2] = [0, 7];

fn attr_base() -> u32 {
    ATTR_FIXED_TPM
        | ATTR_FIXED_PARENT
        | ATTR_SENSITIVE_DATA_ORIGIN
        | ATTR_USER_WITH_AUTH
        | ATTR_NO_DA
}

fn ek_template() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
    p.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    let attrs = attr_base() | ATTR_RESTRICTED | ATTR_DECRYPT;
    p.extend_from_slice(&attrs.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
    p.extend_from_slice(&128u16.to_be_bytes());
    p.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
    p.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    p.extend_from_slice(&2048u16.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p
}

fn ak_template() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
    p.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    let attrs = attr_base() | ATTR_RESTRICTED | ATTR_SIGN;
    p.extend_from_slice(&attrs.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    p.extend_from_slice(&TPM_ALG_RSASSA.to_be_bytes());
    p.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    p.extend_from_slice(&2048u16.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p
}

pub struct LoadedKey {
    pub handle: u32,
    pub public: Vec<u8>,
    pub name_hex: String,
}

impl LoadedKey {
    pub fn ek_hash_hex(&self) -> String {
        crate::crypto::sha256_hex(&self.public)
    }
}

pub struct Tpm {
    ctx: *mut c_void,
}

unsafe impl Send for Tpm {}

impl Tpm {
    pub fn open() -> Result<Tpm> {
        let params = TBS_CONTEXT_PARAMS2 {
            version: TBS_CONTEXT_VERSION_TWO,
            Anonymous: TBS_CONTEXT_PARAMS2_0 { asUINT32: 4 },
        };
        let mut ctx: *mut c_void = std::ptr::null_mut();

        let rc = unsafe {
            Tbsi_Context_Create(
                &params as *const TBS_CONTEXT_PARAMS2 as *const TBS_CONTEXT_PARAMS,
                &mut ctx,
            )
        };
        if rc != 0 || ctx.is_null() {
            return Err(Error::Tpm(format!(
                "no usable TPM 2.0 (TBS 0x{rc:08X}); is the TPM enabled?"
            )));
        }
        Ok(Tpm { ctx })
    }

    fn submit(&self, command: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; 64 * 1024];
        let mut out_len = out.len() as u32;
        let rc = unsafe {
            Tbsip_Submit_Command(
                self.ctx,
                0,
                200,
                command.as_ptr(),
                command.len() as u32,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        if rc != 0 {
            if rc == TBS_COMMAND_BLOCKED {
                return Err(Error::ActivationBlocked);
            }
            return Err(Error::Tpm(format!("TBS submit failed: 0x{rc:08X}")));
        }
        out.truncate(out_len as usize);
        Ok(out)
    }

    fn run(&self, command: &[u8], handles: usize) -> Result<(Vec<u32>, Vec<u8>)> {
        let resp = self.submit(command)?;
        parse_response(&resp, handles)
    }

    pub fn create_ek(&self) -> Result<LoadedKey> {
        self.create_primary(&ek_template())
    }

    pub fn create_ak(&self) -> Result<LoadedKey> {
        self.create_primary(&ak_template())
    }

    fn create_primary(&self, template: &[u8]) -> Result<LoadedKey> {
        let mut params = Vec::new();

        params.extend_from_slice(&4u16.to_be_bytes());
        params.extend_from_slice(&0u16.to_be_bytes());
        params.extend_from_slice(&0u16.to_be_bytes());

        params.extend_from_slice(&(template.len() as u16).to_be_bytes());
        params.extend_from_slice(template);

        params.extend_from_slice(&0u16.to_be_bytes());
        params.extend_from_slice(&0u32.to_be_bytes());

        let mut cmd = command(TPM_CC_CREATE_PRIMARY);
        cmd.extend_from_slice(&TPM_RH_ENDORSEMENT.to_be_bytes());
        cmd.extend_from_slice(&PW_ENTRY_LEN.to_be_bytes());
        append_pw_entry(&mut cmd);
        cmd.extend_from_slice(&params);
        finish(&mut cmd);

        let (handles, out) = self.run(&cmd, 1)?;

        let (public, _) = read_sized(&out, 0)?;
        let handle = handles
            .first()
            .copied()
            .ok_or_else(|| Error::Tpm("CreatePrimary returned no handle".into()))?;
        let mut name = Vec::with_capacity(34);
        name.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        name.extend_from_slice(&crate::crypto::sha256(&public));
        Ok(LoadedKey {
            handle,
            public,
            name_hex: hex::encode(name),
        })
    }

    pub fn quote(
        &self,
        ak: &LoadedKey,
        qualifying_data: &[u8],
        pcrs: &[u32],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut params = Vec::new();
        params.extend_from_slice(&(qualifying_data.len() as u16).to_be_bytes());
        params.extend_from_slice(qualifying_data);
        params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        params.extend_from_slice(&1u32.to_be_bytes());
        params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        let mut mask = [0u8; 3];
        for pcr in pcrs {
            if *pcr >= 24 {
                return Err(Error::Tpm(format!("PCR {pcr} out of range")));
            }
            mask[(*pcr / 8) as usize] |= 1 << (*pcr % 8);
        }
        params.push(3);
        params.extend_from_slice(&mask);

        let mut cmd = command(TPM_CC_QUOTE);
        cmd.extend_from_slice(&ak.handle.to_be_bytes());
        cmd.extend_from_slice(&PW_ENTRY_LEN.to_be_bytes());
        append_pw_entry(&mut cmd);
        cmd.extend_from_slice(&params);
        finish(&mut cmd);

        let (_, out) = self.run(&cmd, 0)?;
        let (attest, next) = read_sized(&out, 0)?;

        Ok((attest, out[next..].to_vec()))
    }

    pub fn activate_credential(
        &self,
        ak: &LoadedKey,
        ek: &LoadedKey,
        id_object: &[u8],
        enc_secret: &[u8],
    ) -> Result<[u8; 32]> {
        let mut params = Vec::new();
        params.extend_from_slice(&(id_object.len() as u16).to_be_bytes());
        params.extend_from_slice(id_object);
        params.extend_from_slice(&(enc_secret.len() as u16).to_be_bytes());
        params.extend_from_slice(enc_secret);

        let mut cmd = command(TPM_CC_ACTIVATE_CREDENTIAL);
        cmd.extend_from_slice(&ak.handle.to_be_bytes());
        cmd.extend_from_slice(&ek.handle.to_be_bytes());
        cmd.extend_from_slice(&(2 * PW_ENTRY_LEN).to_be_bytes());
        append_pw_entry(&mut cmd);
        append_pw_entry(&mut cmd);
        cmd.extend_from_slice(&params);
        finish(&mut cmd);

        let (_, out) = self.run(&cmd, 0)?;
        let (cert_info, _) = read_sized(&out, 0)?;
        if cert_info.len() != 32 {
            return Err(Error::Tpm(format!(
                "certInfo is {} bytes, want 32",
                cert_info.len()
            )));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&cert_info);
        Ok(secret)
    }

    pub fn flush(&self, handle: u32) {
        let mut cmd = command(TPM_CC_FLUSH_CONTEXT);
        cmd.extend_from_slice(&handle.to_be_bytes());
        finish(&mut cmd);
        let _ = self.submit(&cmd);
    }
}

impl Drop for Tpm {
    fn drop(&mut self) {
        unsafe { Tbsip_Context_Close(self.ctx) };
    }
}

fn command(cc: u32) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(64);
    cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&0u32.to_be_bytes());
    cmd.extend_from_slice(&cc.to_be_bytes());
    cmd
}

fn append_pw_entry(cmd: &mut Vec<u8>) {
    cmd.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    cmd.extend_from_slice(&0u16.to_be_bytes());
    cmd.push(0x01);
    cmd.extend_from_slice(&0u16.to_be_bytes());
}

const PW_ENTRY_LEN: u32 = 9;

fn finish(cmd: &mut [u8]) {
    let size = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&size.to_be_bytes());
}

fn parse_response(resp: &[u8], handle_count: usize) -> Result<(Vec<u32>, Vec<u8>)> {
    if resp.len() < 10 {
        return Err(Error::Tpm("response shorter than a header".into()));
    }
    let tag = u16::from_be_bytes([resp[0], resp[1]]);
    let size = u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]) as usize;
    let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    if rc != 0 {
        if rc == TBS_COMMAND_BLOCKED {
            return Err(Error::ActivationBlocked);
        }
        return Err(Error::Tpm(tpm_rc_message(rc)));
    }
    if size > resp.len() || size < 10 {
        return Err(Error::Tpm("response size field is inconsistent".into()));
    }
    let resp = &resp[..size];
    let mut pos = 10;
    let mut handles = Vec::new();
    for _ in 0..handle_count {
        if pos + 4 > resp.len() {
            return Err(Error::Tpm("response truncated in handle area".into()));
        }
        handles.push(u32::from_be_bytes([
            resp[pos],
            resp[pos + 1],
            resp[pos + 2],
            resp[pos + 3],
        ]));
        pos += 4;
    }
    let params = match tag {
        TPM_ST_SESSIONS => {
            if pos + 4 > resp.len() {
                return Err(Error::Tpm(
                    "response truncated before parameter size".into(),
                ));
            }
            let n = u32::from_be_bytes([resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3]])
                as usize;
            pos += 4;
            if pos + n > resp.len() {
                return Err(Error::Tpm("response parameter size out of bounds".into()));
            }
            resp[pos..pos + n].to_vec()
        }
        TPM_ST_NO_SESSIONS => resp[pos..].to_vec(),
        other => return Err(Error::Tpm(format!("unexpected response tag 0x{other:04X}"))),
    };
    Ok((handles, params))
}

fn read_sized(buf: &[u8], pos: usize) -> Result<(Vec<u8>, usize)> {
    if pos + 2 > buf.len() {
        return Err(Error::Tpm("buffer truncated at a size prefix".into()));
    }
    let n = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    let start = pos + 2;
    if start + n > buf.len() {
        return Err(Error::Tpm("buffer truncated inside a sized field".into()));
    }
    Ok((buf[start..start + n].to_vec(), start + n))
}

fn tpm_rc_message(rc: u32) -> String {
    let name = match rc {
        0x0000_0100 => "TPM_RC_INITIALIZE",
        0x0000_0121 => "TPM_RC_FAILURE (TPM in failure mode)",
        0x0000_0098 => "TPM_RC_AUTH_FAIL",
        0x0000_009E => "TPM_RC_POLICY_FAIL",
        0x0000_00A0 => "TPM_RC_INTEGRITY",
        0x0000_009A => "TPM_RC_BAD_AUTH",
        0x0000_01DF => "TPM_RC_COMMAND_CODE",
        0x0000_00C3 => "TPM_RC_ATTRIBUTES",
        0x0000_0084 => "TPM_RC_VALUE",
        0x0000_0080 => "TPM_RC_SIZE",
        0x0000_0184 => "TPM_RC_HANDLE",
        0x0000_0009 => "TPM_RC_DISABLED (TPM is disabled)",
        _ => "TPM_RC",
    };
    format!("TPM error {name} 0x{rc:08X}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ek_template_shape() {
        let t = ek_template();

        assert_eq!(&t[0..2], &[0x00, 0x01]);
        assert_eq!(&t[2..4], &[0x00, 0x0B]);
        let attrs = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        assert_eq!(attrs & ATTR_RESTRICTED, ATTR_RESTRICTED);
        assert_eq!(attrs & ATTR_DECRYPT, ATTR_DECRYPT);
        assert_eq!(attrs & ATTR_USER_WITH_AUTH, ATTR_USER_WITH_AUTH);
        assert_eq!(attrs & ATTR_SIGN, 0);
    }

    #[test]
    fn ak_template_satisfies_the_server_policy() {
        let t = ak_template();
        let attrs = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        assert_eq!(attrs & ATTR_RESTRICTED, ATTR_RESTRICTED);
        assert_eq!(attrs & ATTR_SIGN, ATTR_SIGN);
        assert_eq!(attrs & ATTR_FIXED_TPM, ATTR_FIXED_TPM);
        assert_eq!(attrs & ATTR_FIXED_PARENT, ATTR_FIXED_PARENT);
        assert_eq!(
            attrs & ATTR_SENSITIVE_DATA_ORIGIN,
            ATTR_SENSITIVE_DATA_ORIGIN
        );
        assert_eq!(attrs & ATTR_DECRYPT, 0);
    }

    #[test]
    fn command_header_and_sessions() {
        let mut cmd = command(TPM_CC_QUOTE);
        cmd.extend_from_slice(&0x8000_0001u32.to_be_bytes());
        cmd.extend_from_slice(&PW_ENTRY_LEN.to_be_bytes());
        append_pw_entry(&mut cmd);
        finish(&mut cmd);
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        let size = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]) as usize;
        assert_eq!(size, cmd.len());

        assert_eq!(&cmd[18..22], &0x4000_0009u32.to_be_bytes());
    }

    #[test]
    fn response_parsing_handles_and_params() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        resp.extend_from_slice(&0x0300_0000u32.to_be_bytes());
        resp.extend_from_slice(&3u32.to_be_bytes());
        resp.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        resp.extend_from_slice(&0u32.to_be_bytes());
        let size = resp.len() as u32;
        resp[2..6].copy_from_slice(&size.to_be_bytes());

        let (handles, params) = parse_response(&resp, 1).unwrap();
        assert_eq!(handles, vec![0x0300_0000]);
        assert_eq!(params, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn response_parsing_reports_rc() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        resp.extend_from_slice(&10u32.to_be_bytes());
        resp.extend_from_slice(&0x0000_0098u32.to_be_bytes());
        let err = parse_response(&resp, 0).unwrap_err();
        assert!(format!("{err}").contains("AUTH_FAIL"));
    }

    #[test]
    fn blocked_command_maps_to_activation_blocked() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        resp.extend_from_slice(&10u32.to_be_bytes());
        resp.extend_from_slice(&TBS_COMMAND_BLOCKED.to_be_bytes());
        assert!(matches!(
            parse_response(&resp, 0),
            Err(Error::ActivationBlocked)
        ));
    }

    #[test]
    fn read_sized_bounds() {
        let buf = [0x00, 0x02, 0x11, 0x22, 0xFF];
        let (content, next) = read_sized(&buf, 0).unwrap();
        assert_eq!(content, vec![0x11, 0x22]);
        assert_eq!(next, 4);
        assert!(read_sized(&buf, 3).is_err());
        assert!(read_sized(&[0x00, 0x05, 0x01], 0).is_err());
    }
}
