use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Config(String),
    Transport(String),
    Api {
        status: u16,
        code: String,
        message: String,
        retry_after_s: u32,
    },

    NeedOob {
        expires_at: i64,
    },

    InvalidCode {
        attempts_remaining: Option<u32>,
    },

    CodeLocked {
        retry_after_s: u32,
    },

    SessionLost(String),
    State(String),
    Tpm(String),
    ActivationBlocked,
    Package(String),
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(m) => write!(f, "config: {m}"),
            Error::Transport(m) => write!(f, "network: {m}"),
            Error::Api {
                status,
                code,
                message,
                retry_after_s,
            } => {
                write!(f, "server {status} {code}: {message}")?;
                if *retry_after_s > 0 {
                    write!(f, " (retry in ~{retry_after_s}s)")?;
                }
                Ok(())
            }
            Error::NeedOob { expires_at } => {
                write!(f, "activation code required (expires at {expires_at})")
            }
            Error::InvalidCode {
                attempts_remaining,
            } => match attempts_remaining {
                Some(n) => write!(f, "wrong activation code, {n} attempts left"),
                None => write!(f, "wrong activation code"),
            },
            Error::CodeLocked { retry_after_s } => {
                write!(f, "activation code locked for {retry_after_s}s")
            }
            Error::SessionLost(m) => write!(f, "session lost: {m}"),
            Error::State(m) => write!(f, "state: {m}"),
            Error::Tpm(m) => write!(f, "tpm: {m}"),
            Error::ActivationBlocked => write!(
                f,
                "tpm: ActivateCredential is blocked for this process (run elevated for full attestation)"
            ),
            Error::Package(m) => write!(f, "package: {m}"),
            Error::Protocol(m) => write!(f, "protocol: {m}"),
        }
    }
}

impl std::error::Error for Error {}
