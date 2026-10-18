use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eh_client::{Activation, Client, Config, Error};

struct Args {
    server: String,
    license: String,
    data_dir: PathBuf,
    code: Option<String>,
    ca: Option<PathBuf>,
    pin: Option<String>,
    fingerprint: Option<String>,
    package_id: Option<String>,
    package_file: Option<PathBuf>,
    no_tpm: bool,
    json: bool,
    heartbeats: u32,
    exec_vm: bool,
}

const USAGE: &str = "\
eh-demo — Event Horizon client walkthrough

USAGE:
  eh-demo --server <https://host:port> --license <key> --data-dir <dir> [options]

OPTIONS:
  --code <8 digits>     out-of-band activation code
  --ca <file.pem>       trust this CA (self-hosted servers)
  --pin <hex32>         pin the server certificate SPKI (sha256, 64 hex)
  --fp <hex64>          override the machine fingerprint (tools/tests)
  --package-id <id>     request this package on verify
  --package-file <file> .ehpkg container to open once the key is delivered
  --heartbeats <n>      send n heartbeats (default 2)
  --no-tpm              skip TPM attestation entirely
  --exec-vm             run an EHVM1 payload with the session seed
  --json                machine-readable output
  -h, --help            this text
";

fn parse_args(mut argv: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut args = Args {
        server: String::new(),
        license: String::new(),
        data_dir: PathBuf::new(),
        code: None,
        ca: None,
        pin: None,
        fingerprint: None,
        package_id: None,
        package_file: None,
        no_tpm: false,
        json: false,
        heartbeats: 2,
        exec_vm: false,
    };
    while let Some(flag) = argv.next() {
        let mut value = |name: &str| -> Result<String, String> {
            argv.next()
                .ok_or_else(|| format!("{name} needs a value; try --help"))
        };
        match flag.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--server" => args.server = value("--server")?,
            "--license" => args.license = value("--license")?,
            "--data-dir" => args.data_dir = PathBuf::from(value("--data-dir")?),
            "--code" => args.code = Some(value("--code")?),
            "--ca" => args.ca = Some(PathBuf::from(value("--ca")?)),
            "--pin" => args.pin = Some(value("--pin")?),
            "--fp" => args.fingerprint = Some(value("--fp")?),
            "--package-id" => args.package_id = Some(value("--package-id")?),
            "--package-file" => args.package_file = Some(PathBuf::from(value("--package-file")?)),
            "--heartbeats" => {
                args.heartbeats = value("--heartbeats")?
                    .parse()
                    .map_err(|_| "--heartbeats takes a number".to_string())?
            }
            "--no-tpm" => args.no_tpm = true,
            "--exec-vm" => args.exec_vm = true,
            "--json" => args.json = true,
            other => return Err(format!("unknown flag {other}; try --help")),
        }
    }
    if args.server.is_empty() || args.license.is_empty() || args.data_dir.as_os_str().is_empty() {
        return Err("--server, --license and --data-dir are required".into());
    }
    Ok(args)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("eh-demo: {e}");
            return ExitCode::from(1);
        }
    };
    match run(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("eh-demo: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(args: Args) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut cfg = Config::new(&args.server, &args.license, args.data_dir.clone());
    if let Some(ca) = &args.ca {
        cfg.http.ca_pem = Some(std::fs::read(ca)?);
    }
    if let Some(pin) = &args.pin {
        cfg.http.spki_pin = Some(parse_pin(pin)?);
    }
    cfg.fingerprint_override = args.fingerprint.clone();
    cfg.package_id = args.package_id.clone();
    cfg.package_file = args.package_file.clone();
    cfg.use_tpm = !args.no_tpm;

    let mut client = Client::new(cfg)?;

    if client.session().is_none() {
        match client.activate(args.code.as_deref())? {
            Activation::Ready => {}
            Activation::NeedOob { expires_at } => {
                print_summary(&client, &args, Some(expires_at));
                return Ok(ExitCode::from(2));
            }
        }
    }

    if client.session().is_none() {
        if let Tick::NeedOob(expires_at) = reconnect(&mut client, args.code.as_deref())? {
            print_summary(&client, &args, Some(expires_at));
            return Ok(ExitCode::from(2));
        }
    }
    for _ in 0..args.heartbeats {
        if let Tick::NeedOob(expires_at) = heartbeat(&mut client, args.code.as_deref())? {
            print_summary(&client, &args, Some(expires_at));
            return Ok(ExitCode::from(2));
        }
    }

    print_summary(&client, &args, None);

    if args.exec_vm {
        if let Some(payload) = client.payload() {
            if payload.starts_with(eh_core::MAGIC) {
                let program = eh_core::Bytecode::parse(payload)?;
                let seed = *client.session().expect("session exists").vm_seed();
                let output = eh_core::Vm::with_seed(seed).run(&program)?;
                println!(
                    "vm output ({} bytes): {}",
                    output.len(),
                    String::from_utf8_lossy(&output)
                );
            } else {
                println!("payload is not an EHVM1 program; skipping --exec-vm");
            }
        } else {
            println!("no payload opened; skipping --exec-vm");
        }
    }

    Ok(ExitCode::SUCCESS)
}

enum Tick {
    Ok,
    NeedOob(i64),
}

fn reconnect(client: &mut Client, code: Option<&str>) -> Result<Tick, Box<dyn std::error::Error>> {
    match client.establish() {
        Ok(()) => Ok(Tick::Ok),
        Err(Error::NeedOob { .. }) => match client.activate(code)? {
            Activation::Ready => {
                client.establish()?;
                Ok(Tick::Ok)
            }
            Activation::NeedOob { expires_at } => Ok(Tick::NeedOob(expires_at)),
        },
        Err(e) => Err(e.into()),
    }
}

fn heartbeat(client: &mut Client, code: Option<&str>) -> Result<Tick, Box<dyn std::error::Error>> {
    match client.heartbeat() {
        Ok(()) => Ok(Tick::Ok),
        Err(Error::SessionLost(_)) => match reconnect(client, code)? {
            Tick::Ok => {
                client.heartbeat()?;
                Ok(Tick::Ok)
            }
            need => Ok(need),
        },
        Err(Error::Api {
            code: err_code,
            retry_after_s,
            ..
        }) if err_code == eh_client::wire::CODE_RATE_LIMITED => {
            let wait = retry_after_s.clamp(1, 60);
            std::thread::sleep(Duration::from_secs(wait as u64));
            match client.heartbeat() {
                Ok(()) => Ok(Tick::Ok),
                Err(Error::SessionLost(_)) => match reconnect(client, code)? {
                    Tick::Ok => {
                        client.heartbeat()?;
                        Ok(Tick::Ok)
                    }
                    need => Ok(need),
                },
                Err(e) => Err(e.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

fn print_summary(client: &Client, args: &Args, need_oob_expires: Option<i64>) {
    let session = client.session();
    if args.json {
        let out = serde_json::json!({
            "status": if need_oob_expires.is_some() { "oob_required" } else { "ok" },
            "oob_expires_at": need_oob_expires,
            "fingerprint": client.fingerprint(),
            "session_id": session.map(|s| s.id.clone()),
            "trust": session.map(|s| s.trust.clone()),
            "lease_exp": session.map(|s| s.lease_exp),
            "lease_left_s": session.map(|s| s.lease_exp - now()),
            "usable_offline": client.usable_offline(),
            "usable_until": session.map(|s| s.usable_until()),
            "heartbeat_interval_s": session.map(|s| s.heartbeat_interval_s),
            "package_id": session.and_then(|s| s.package()).map(|p| p.id.clone()),
            "package_sha256": session.and_then(|s| s.package()).map(|p| p.sha256.clone()),
            "payload_len": client.payload().map(|p| p.len()),
            "notes": client.notes(),
        });
        println!("{out}");
        return;
    }

    if let Some(expires) = need_oob_expires {
        println!("activation needs an out-of-band code (expires at {expires}).");
        println!("An administrator gets it with:");
        println!("  ehctl license oob <license-id>");
        println!("Then re-run this command with --code <8 digits>.");
        return;
    }

    println!("fingerprint : {}", client.fingerprint());
    match session {
        Some(s) => {
            println!("session     : {}", s.id);
            println!("trust       : {}", s.trust);
            println!(
                "lease       : {}s left (heartbeat every {}s)",
                s.lease_exp - now(),
                s.heartbeat_interval_s
            );
            println!(
                "offline     : usable until {} ({}s of grace)",
                s.usable_until(),
                s.offline_grace_s
            );
            if let Some(p) = s.package() {
                println!("package     : {} ({})", p.id, p.sha256);
            }
        }
        None => println!("session     : none"),
    }
    if let Some(payload) = client.payload() {
        println!("payload     : {} bytes opened", payload.len());
    }
    for note in client.notes() {
        println!("note        : {note}");
    }
}

fn parse_pin(text: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let raw = hex::decode(text.trim())?;
    if raw.len() != 32 {
        return Err("--pin must be 32 bytes of hex (sha256 of the SPKI)".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}
