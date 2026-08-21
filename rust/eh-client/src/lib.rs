#![allow(clippy::missing_safety_doc)]

pub mod client;
pub mod crypto;
pub mod dpapi;
pub mod error;
pub mod ffi;
pub mod fingerprint;
pub mod http;
pub mod packaging;
pub mod state;
pub mod wire;

#[cfg(windows)]
pub mod tpm;

pub use client::{Activation, Client, Config, Session};
pub use error::{Error, Result};
pub use http::HttpConfig;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
