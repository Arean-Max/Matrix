use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::thread;
use std::time::{Duration, Instant};

use eh_client::guard::GuardConfig;
use eh_client::{Activation, Client, Config, Error};

const USAGE: &str = "\
eh-guard - verify a license and launch a protected application

USAGE:
  eh-guard --config guard.json [--code 12345678] [--] [child arguments...]

OPTIONS:
  --config FILE         guard configuration (default: guard.json)
  --code 8 digits       out-of-band activation code
  -h, --help            this text
";

struct Args {
    config_path: PathBuf,
    code: Option<String>,
    child_args: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = env::args().skip(1);
    let mut config_path = PathBuf::from("guard.json");
    let mut code = None;
    let mut child_args = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let val = args.next().ok_or("--config requires a file path")?;
                config_path = PathBuf::from(val);
            }
            "--code" => {
                let val = args.next().ok_or("--code requires an 8-digit code")?;
                code = Some(val);
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--" => {
                child_args.extend(args);
                break;
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option: {other}\n{USAGE}"));
            }
            other => {
                child_args.push(other.to_string());
                child_args.extend(args);
                break;
            }
        }
    }

    Ok(Args {
        config_path,
        code,
        child_args,
    })
}

struct StagedFileGuard {
    path: PathBuf,
}

impl Drop for StagedFileGuard {
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    let guard_cfg = match GuardConfig::load_from_file(&args.config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("eh-guard: config: {e}");
            return ExitCode::from(1);
        }
    };

    let license = match guard_cfg.resolve_license() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("eh-guard: license: {e}");
            return ExitCode::from(1);
        }
    };

    let data_dir = guard_cfg
        .data_dir
        .clone()
        .unwrap_or_else(|| env::temp_dir().join("eh-guard-state"));
    let _ = fs::create_dir_all(&data_dir);

    let mut cfg = Config::new(&guard_cfg.server, &license, data_dir);
    if let Some(ref ca) = guard_cfg.ca_file {
        cfg.http.ca_pem_path = Some(ca.clone());
    }
    if let Some(ref pin) = guard_cfg.spki_pin {
        cfg.http.spki_pin_hex = Some(pin.clone());
    }
    cfg.use_tpm = !guard_cfg.no_tpm;
    if let Some(ref pid) = guard_cfg.package_id {
        cfg.package_id = Some(pid.clone());
    }
    if let Some(ref pf) = guard_cfg.package_file {
        cfg.package_file = Some(pf.clone());
    }

    let mut client = match Client::new(cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("eh-guard: client: {e}");
            return ExitCode::from(1);
        }
    };

    let needs_activation = client.session().is_none() || !client.usable_offline();
    if needs_activation {
        match client.activate(args.code.as_deref()) {
            Ok(Activation::Ready) => {}
            Ok(Activation::NeedOob { expires_at }) => {
                eprintln!("eh-guard: activation needs an out-of-band code (expires at {expires_at})");
                eprintln!("eh-guard: an administrator can reveal it with: ehctl license oob <license-id>");
                return ExitCode::from(1);
            }
            Err(e) => {
                eprintln!("eh-guard: client: {e}");
                return ExitCode::from(1);
            }
        }
    }

    if let Err(e) = client.verify() {
        if !needs_activation {
            // Re-attempt activation in case session was revoked or expired on server
            match client.activate(args.code.as_deref()) {
                Ok(Activation::Ready) => {
                    if let Err(e) = client.verify() {
                        eprintln!("eh-guard: client: {e}");
                        return ExitCode::from(1);
                    }
                }
                Ok(Activation::NeedOob { expires_at }) => {
                    eprintln!("eh-guard: activation needs an out-of-band code (expires at {expires_at})");
                    eprintln!("eh-guard: an administrator can reveal it with: ehctl license oob <license-id>");
                    return ExitCode::from(1);
                }
                Err(e) => {
                    eprintln!("eh-guard: client: {e}");
                    return ExitCode::from(1);
                }
            }
        } else {
            eprintln!("eh-guard: client: {e}");
            return ExitCode::from(1);
        }
    }

    let mut _file_guard: Option<StagedFileGuard> = None;
    let exec_path = if guard_cfg.package_file.is_some() {
        let payload = match client.payload() {
            Some(p) => p,
            None => {
                eprintln!("eh-guard: no payload was delivered for the requested package");
                return ExitCode::from(1);
            }
        };
        let staging_dir = guard_cfg.staging_dir.clone().unwrap_or_else(|| {
            env::temp_dir().join(format!(".eh_stage_{}", std::process::id()))
        });
        let _ = fs::create_dir_all(&staging_dir);
        use rand::RngCore;
        let mut nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);
        let nonce_hex = hex::encode(nonce);
        let staged_file = staging_dir.join(format!("eh_staged_{}_{}.exe", std::process::id(), nonce_hex));
        if let Err(e) = fs::write(&staged_file, payload) {
            eprintln!("eh-guard: failed to write staged executable: {e}");
            return ExitCode::from(1);
        }
        _file_guard = Some(StagedFileGuard {
            path: staged_file.clone(),
        });
        staged_file
    } else {
        guard_cfg.executable.clone().unwrap()
    };

    let mut cmd = Command::new(&exec_path);
    let mut final_args = guard_cfg.args.clone();
    final_args.extend(args.child_args);
    cmd.args(&final_args);
    for (k, v) in &guard_cfg.env {
        cmd.env(k, v);
    }
    if let Some(ref wd) = guard_cfg.working_dir {
        cmd.current_dir(wd);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("eh-guard: failed to spawn child process: {e}");
            return ExitCode::from(1);
        }
    };

    let interval_s = client
        .session()
        .map(|s| s.heartbeat_interval_s.max(5) as u64)
        .unwrap_or(60);
    let kill_on_expiry = guard_cfg.kill_on_lease_expiry;

    let mut last_hb = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {}
            Err(e) => break Err(e),
        }

        if last_hb.elapsed() >= Duration::from_secs(interval_s) {
            match client.heartbeat() {
                Ok(()) => {
                    last_hb = Instant::now();
                }
                Err(e) => {
                    let offline_ok = client.usable_offline();
                    if !offline_ok || matches!(e, Error::SessionLost(_)) {
                        eprintln!("eh-guard: session expired or revoked ({e}); terminating protected process");
                        if kill_on_expiry {
                            let _ = child.kill();
                        }
                        let _ = child.wait();
                        return ExitCode::from(1);
                    }
                    last_hb = Instant::now();
                }
            }
        }

        thread::sleep(Duration::from_millis(150));
    };

    match status {
        Ok(s) => ExitCode::from(s.code().unwrap_or(0) as u8),
        Err(e) => {
            eprintln!("eh-guard: child wait failed: {e}");
            ExitCode::from(1)
        }
    }
}
