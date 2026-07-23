mod tpm;
mod verify;

use std::io::{BufRead, BufWriter, Write};

use base64::Engine;
use serde::{Deserialize, Serialize};

const MAX_LINE: usize = 1 << 20;
const PROTOCOL: u32 = 1;

#[derive(Deserialize)]
#[serde(tag = "op")]
enum Request {
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "check_ak")]
    CheckAk { ak_pub: String },
    #[serde(rename = "verify_quote")]
    VerifyQuote {
        ak_pub: String,
        attest: String,
        signature: String,
        ak_name: String,
        nonce: String,
    },
}

#[derive(Serialize)]
struct Response {
    protocol: u32,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ak_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quote: Option<QuoteOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct QuoteOut {
    pcr_digest: String,
    pcrs: Vec<u16>,
    clock_ms: u64,
    reset_count: u32,
    restart_count: u32,
    safe: bool,
    firmware_version: u64,
}

impl Response {
    fn ok() -> Self {
        Self {
            protocol: PROTOCOL,
            ok: true,
            ak_name: None,
            quote: None,
            error: None,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            protocol: PROTOCOL,
            ok: false,
            ak_name: None,
            quote: None,
            error: Some(message.into()),
        }
    }
}

fn decode_b64(value: &str, max: usize) -> Result<Vec<u8>, String> {
    if value.len() > max.div_ceil(3) * 4 {
        return Err("field is too large".to_string());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| "invalid base64".to_string())?;
    if bytes.len() > max {
        return Err("field is too large".to_string());
    }
    Ok(bytes)
}

fn decode_hex(value: &str, max: usize) -> Result<Vec<u8>, String> {
    if value.len() > max * 2 {
        return Err("field is too large".to_string());
    }
    hex::decode(value).map_err(|_| "invalid hex".to_string())
}

fn quote_out(quote: tpm::Quote) -> QuoteOut {
    QuoteOut {
        pcr_digest: hex::encode(quote.pcr_digest),
        pcrs: quote.pcrs,
        clock_ms: quote.clock_ms,
        reset_count: quote.reset_count,
        restart_count: quote.restart_count,
        safe: quote.safe,
        firmware_version: quote.firmware_version,
    }
}

fn handle(line: &str) -> Response {
    let request: Request = match serde_json::from_str(line) {
        Ok(request) => request,
        Err(err) => return Response::error(format!("invalid request: {err}")),
    };
    match request {
        Request::Ping => Response::ok(),
        Request::CheckAk { ak_pub } => {
            let ak_pub = match decode_b64(&ak_pub, 2048) {
                Ok(value) => value,
                Err(err) => return Response::error(err),
            };
            match verify::check_ak(&ak_pub) {
                Ok(name) => Response {
                    protocol: PROTOCOL,
                    ok: true,
                    ak_name: Some(hex::encode(name)),
                    quote: None,
                    error: None,
                },
                Err(err) => Response::error(err),
            }
        }
        Request::VerifyQuote {
            ak_pub,
            attest,
            signature,
            ak_name,
            nonce,
        } => {
            let ak_pub = match decode_b64(&ak_pub, 2048) {
                Ok(value) => value,
                Err(err) => return Response::error(err),
            };
            let attest = match decode_b64(&attest, 4096) {
                Ok(value) => value,
                Err(err) => return Response::error(err),
            };
            let signature = match decode_b64(&signature, 1024) {
                Ok(value) => value,
                Err(err) => return Response::error(err),
            };
            let nonce = match decode_hex(&nonce, 64) {
                Ok(value) => value,
                Err(err) => return Response::error(err),
            };
            let ak_name = match decode_hex(&ak_name, 128) {
                Ok(value) => value,
                Err(err) => return Response::error(err),
            };
            match verify::verify_quote(&ak_pub, &attest, &signature, &ak_name, &nonce) {
                Ok(quote) => Response {
                    protocol: PROTOCOL,
                    ok: true,
                    ak_name: None,
                    quote: Some(quote_out(quote)),
                    error: None,
                },
                Err(err) => Response::error(err),
            }
        }
    }
}

enum Line {
    Ok(String),
    TooLong,
}

// next_line never allocates more than `max` bytes for one request, even when
// the peer sends a line without a newline.
fn next_line<R: BufRead>(r: &mut R, max: usize) -> std::io::Result<Option<Line>> {
    let mut buf = Vec::new();
    let mut too_long = false;
    loop {
        let (n, pos) = {
            let chunk = r.fill_buf()?;
            if chunk.is_empty() {
                if buf.is_empty() && !too_long {
                    return Ok(None);
                }
                break;
            }
            let pos = chunk.iter().position(|&b| b == b'\n');
            let n = pos.map(|p| p + 1).unwrap_or(chunk.len());
            if let Some(p) = pos {
                if !too_long {
                    if buf.len() + p > max {
                        too_long = true;
                    } else {
                        buf.extend_from_slice(&chunk[..p]);
                    }
                }
            } else if !too_long {
                if buf.len() + chunk.len() > max {
                    too_long = true;
                    buf.clear();
                } else {
                    buf.extend_from_slice(chunk);
                }
            }
            (n, pos)
        };
        r.consume(n);
        if pos.is_some() {
            break;
        }
    }
    if too_long {
        return Ok(Some(Line::TooLong));
    }
    match String::from_utf8(buf) {
        Ok(s) => Ok(Some(Line::Ok(s))),
        Err(_) => Ok(Some(Line::TooLong)),
    }
}

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut input = stdin.lock();
    loop {
        let line = match next_line(&mut input, MAX_LINE) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(_) => break,
        };
        let line = match line {
            Line::Ok(line) if line.trim().is_empty() => continue,
            Line::Ok(line) => line,
            Line::TooLong => {
                let response = Response::error("request is too large");
                if serde_json::to_writer(&mut out, &response).is_err()
                    || out.write_all(b"\n").is_err()
                    || out.flush().is_err()
                {
                    break;
                }
                continue;
            }
        };
        let response = handle(&line);
        if serde_json::to_writer(&mut out, &response).is_err() {
            break;
        }
        if out.write_all(b"\n").is_err() || out.flush().is_err() {
            break;
        }
    }
}
