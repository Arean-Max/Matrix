use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    pub server: String,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub license_file: Option<PathBuf>,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub spki_pin: Option<String>,
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    #[serde(default)]
    pub executable: Option<PathBuf>,
    #[serde(default)]
    pub package_file: Option<PathBuf>,
    #[serde(default)]
    pub package_id: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub working_dir: Option<PathBuf>,
    #[serde(default)]
    pub staging_dir: Option<PathBuf>,
    #[serde(default)]
    pub no_tpm: bool,
    #[serde(default = "default_kill_on_lease_expiry")]
    pub kill_on_lease_expiry: bool,
    #[serde(default)]
    pub min_trust: Option<String>,
}

fn default_kill_on_lease_expiry() -> bool {
    true
}

impl GuardConfig {
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            Error::Config(format!(
                "failed to read guard config {}: {e}",
                path.display()
            ))
        })?;
        let config: GuardConfig = serde_json::from_str(&content)
            .map_err(|e| Error::Config(format!("failed to parse guard config: {e}")))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.server.trim().is_empty() {
            return Err(Error::Config("server is required".into()));
        }
        if self.license.is_none() && self.license_file.is_none() {
            return Err(Error::Config(
                "set license or license_file in the guard config".into(),
            ));
        }
        if self.package_file.is_some() && self.executable.is_some() {
            return Err(Error::Config(
                "set either package_file or executable, not both".into(),
            ));
        }
        if self.package_file.is_none() && self.executable.is_none() {
            return Err(Error::Config(
                "set package_file or executable in the guard config".into(),
            ));
        }
        if self.package_file.is_some() && self.package_id.is_none() {
            return Err(Error::Config("package_file requires package_id".into()));
        }
        Ok(())
    }

    pub fn resolve_license(&self) -> Result<String> {
        if let Some(ref l) = self.license {
            let trimmed = l.trim();
            if trimmed.is_empty() {
                return Err(Error::Config("license is empty".into()));
            }
            return Ok(trimmed.to_string());
        }
        if let Some(ref lf) = self.license_file {
            let content = fs::read_to_string(lf).map_err(|e| {
                Error::Config(format!("cannot read license file {}: {e}", lf.display()))
            })?;
            let trimmed = content.trim();
            if trimmed.is_empty() {
                return Err(Error::Config(format!(
                    "license file is empty: {}",
                    lf.display()
                )));
            }
            return Ok(trimmed.to_string());
        }
        Err(Error::Config(
            "set license or license_file in the guard config".into(),
        ))
    }
}
