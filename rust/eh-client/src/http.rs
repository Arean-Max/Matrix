// Initial WinHTTP transport implementation via windows-sys
// Deprecated by ADR-018 in favor of ureq + rustls
use crate::error::Result;

pub struct HttpClient {
    endpoint: String,
}

impl HttpClient {
    pub fn new(endpoint: &str) -> Self {
        Self { endpoint: endpoint.to_string() }
    }

    pub fn post_json(&self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
