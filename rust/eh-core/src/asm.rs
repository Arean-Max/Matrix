use std::error::Error;
use std::fmt;

use crate::vm::op;
use crate::{Bytecode, WORD};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsmError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for AsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "{}", self.message)
        } else {
            write!(f, "line {}: {}", self.line, self.message)
        }
    }
}

impl Error for AsmError {}

fn err(line: usize, message: impl Into<String>) -> AsmError {
    AsmError {
        line,
        message: message.into(),
    }
}

#[derive(Clone, Debug)]
enum Imm {
    None,
    U8(u8),
    U16(u16),
    Jump(JumpRef),
}

#[derive(Clone, Debug)]
enum JumpRef {
    Label(String),
    Rel(i64),
}

#[derive(Clone, Debug)]
struct Op {
    code: u8,
    imm: Imm,
    line: usize,
}

impl Op {
    fn byte_len(&self) -> usize {
        1 + match self.imm {
            Imm::None => 0,
            Imm::U8(_) => 1,
            Imm::U16(_) => 2,
            Imm::Jump(_) => 2,
        }
    }
}

pub fn assemble(source: &str) -> Result<Vec<u8>, AsmError> {
    let prog = assemble_bytecode(source)?;
    Ok(prog.to_bytes())
}

pub fn assemble_bytecode(source: &str) -> Result<Bytecode, AsmError> {
    let mut consts: Vec<[u8; WORD]> = Vec::new();
    let mut ops: Vec<Op> = Vec::new();
    let mut labels: Vec<(String, usize)> = Vec::new();

    for (idx, raw) in source.lines().enumerate() {
        let line = idx + 1;
        let text = strip_comment(raw).trim();
        if text.is_empty() {
            continue;
        }
        if let Some(rest) = text.strip_prefix('.') {
            let (dir, arg) = split_word(rest);
            match dir {
                "const" => consts.push(parse_const(arg.trim(), line)?),
                other => return Err(err(line, format!("unknown directive .{other}"))),
            }
            continue;
        }
        if let Some(name) = text.strip_suffix(':') {
            let name = name.trim();
            if name.is_empty() {
                return Err(err(line, "empty label"));
            }
            if labels.iter().any(|(n, _)| n == name) {
                return Err(err(line, format!("duplicate label {name}")));
            }
            labels.push((name.to_string(), ops.len()));
            continue;
        }

        let (mnemonic, arg) = split_word(text);
        let arg = arg.trim();
        let (code, imm) = match mnemonic {
            "halt" | "dup" | "drop" | "swap" | "xor" | "add" | "sha" | "hmac" | "cmp" | "out" => {
                no_arg(arg, line, mnemonic)?;
                (
                    match mnemonic {
                        "halt" => op::HALT,
                        "dup" => op::DUP,
                        "drop" => op::DROP,
                        "swap" => op::SWAP,
                        "xor" => op::XOR,
                        "add" => op::ADD,
                        "sha" => op::SHA,
                        "hmac" => op::HMAC,
                        "cmp" => op::CMP,
                        _ => op::OUT,
                    },
                    Imm::None,
                )
            }
            "seed" => {
                no_arg(arg, line, mnemonic)?;
                (op::SEED, Imm::None)
            }
            "push" => (op::PUSH, Imm::U16(parse_u16(arg, line, "const index")?)),
            "load" | "store" | "input" => {
                let slot = parse_u8(arg, line, "slot")?;
                let code = match mnemonic {
                    "load" => op::LOAD,
                    "store" => op::STORE,
                    _ => op::INPUT,
                };
                (code, Imm::U8(slot))
            }
            "jnz" => {
                let imm = if let Some(rest) = arg.strip_prefix('+') {
                    Imm::Jump(JumpRef::Rel(parse_i64(rest, line, "offset")?))
                } else if arg.starts_with('-') {
                    Imm::Jump(JumpRef::Rel(parse_i64(arg, line, "offset")?))
                } else {
                    if arg.is_empty() {
                        return Err(err(line, "jnz needs a label or offset"));
                    }
                    Imm::Jump(JumpRef::Label(arg.to_string()))
                };
                (op::JNZ, imm)
            }
            other => return Err(err(line, format!("unknown instruction {other:?}"))),
        };
        if let Imm::U16(i) = imm {
            if code == op::PUSH && i as usize >= consts.len() {
                return Err(err(
                    line,
                    format!("const index {i} out of range ({} constants)", consts.len()),
                ));
            }
        }
        ops.push(Op { code, imm, line });
    }

    let mut offsets = Vec::with_capacity(ops.len());
    let mut total = 0usize;
    for o in &ops {
        offsets.push(total);
        total += o.byte_len();
    }
    let label_offset = |name: &str| -> Option<usize> {
        labels.iter().find(|(n, _)| n == name).map(|(_, i)| {
            if *i < offsets.len() {
                offsets[*i]
            } else {
                total
            }
        })
    };

    let mut code = Vec::with_capacity(total);
    for (i, o) in ops.iter().enumerate() {
        code.push(o.code);
        match &o.imm {
            Imm::None => {}
            Imm::U8(v) => code.push(*v),
            Imm::U16(v) => code.extend_from_slice(&v.to_be_bytes()),
            Imm::Jump(jr) => {
                let target = match jr {
                    JumpRef::Label(name) => label_offset(name)
                        .ok_or_else(|| err(o.line, format!("unknown label {name}")))?,
                    JumpRef::Rel(r) => {
                        let after = (offsets[i] + 3) as i64;
                        let t = after + r;
                        if t < 0 || t as usize > total {
                            return Err(err(o.line, "relative jump out of range"));
                        }
                        t as usize
                    }
                };
                let delta = target as i64 - (offsets[i] as i64 + 3);
                if !(-32768..=32767).contains(&delta) {
                    return Err(err(o.line, "jump distance exceeds i16"));
                }
                code.extend_from_slice(&(delta as i16).to_be_bytes());
            }
        }
    }
    debug_assert_eq!(code.len(), total);

    Ok(Bytecode { consts, code })
}

fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    for (i, ch) in line.char_indices() {
        match ch {
            '"' => in_string = !in_string,
            ';' if !in_string => return &line[..i],
            _ => {}
        }
    }
    line
}

fn split_word(text: &str) -> (&str, &str) {
    match text.find(char::is_whitespace) {
        Some(i) => (&text[..i], text[i..].trim_start()),
        None => (text, ""),
    }
}

fn no_arg(arg: &str, line: usize, mnemonic: &str) -> Result<(), AsmError> {
    if arg.is_empty() {
        Ok(())
    } else {
        Err(err(line, format!("{mnemonic} takes no argument")))
    }
}

fn parse_const(arg: &str, line: usize) -> Result<[u8; WORD], AsmError> {
    enum Kind {
        Text,
        Number,
    }
    let (mut bytes, kind): (Vec<u8>, Kind) = if let Some(text) = arg.strip_prefix('"') {
        let inner = text
            .strip_suffix('"')
            .ok_or_else(|| err(line, "unterminated string constant"))?;
        (inner.bytes().collect(), Kind::Text)
    } else if let Some(hexpart) = arg.strip_prefix("0x").or_else(|| arg.strip_prefix("0X")) {
        if hexpart.len() % 2 != 0 {
            return Err(err(line, "hex constant needs an even number of digits"));
        }
        let mut out = Vec::with_capacity(hexpart.len() / 2);
        let hb = hexpart.as_bytes();
        for pair in hb.chunks(2) {
            let hi = hexval(pair[0]).ok_or_else(|| err(line, "bad hex digit"))?;
            let lo = hexval(pair[1]).ok_or_else(|| err(line, "bad hex digit"))?;
            out.push((hi << 4) | lo);
        }
        (out, Kind::Number)
    } else {
        return Err(err(line, "constants are 0xHEX or \"ascii\""));
    };
    if bytes.len() > WORD {
        return Err(err(line, "constant is longer than 32 bytes"));
    }
    let mut word = [0u8; WORD];
    match kind {
        Kind::Text => word[..bytes.len()].copy_from_slice(&bytes),
        Kind::Number => {
            let off = WORD - bytes.len();
            word[off..].copy_from_slice(&bytes)
        }
    }
    bytes.clear();
    Ok(word)
}

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_u8(arg: &str, line: usize, what: &str) -> Result<u8, AsmError> {
    let v = parse_uint(arg, line, what)?;
    u8::try_from(v).map_err(|_| err(line, format!("{what} {v} out of range")))
}

fn parse_u16(arg: &str, line: usize, what: &str) -> Result<u16, AsmError> {
    let v = parse_uint(arg, line, what)?;
    u16::try_from(v).map_err(|_| err(line, format!("{what} {v} out of range")))
}

fn parse_uint(arg: &str, line: usize, what: &str) -> Result<u64, AsmError> {
    let body = arg.strip_prefix('+').unwrap_or(arg);
    let (radix, digits) = match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        Some(hex) => (16, hex),
        None => (10, body),
    };
    u64::from_str_radix(digits, radix)
        .map_err(|_| err(line, format!("{what} must be a number, got {arg:?}")))
}

fn parse_i64(arg: &str, line: usize, what: &str) -> Result<i64, AsmError> {
    let (negative, body) = match arg.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, arg.strip_prefix('+').unwrap_or(arg)),
    };
    let (radix, digits) = match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        Some(hex) => (16, hex),
        None => (10, body),
    };
    let v = i128::from_str_radix(digits, radix)
        .map_err(|_| err(line, format!("{what} must be a number, got {arg:?}")))?;
    let v = if negative { -v } else { v };
    i64::try_from(v).map_err(|_| err(line, format!("{what} {arg} out of range")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::Vm;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    #[test]
    fn consts_parse_hex_and_ascii() {
        let c = parse_const("0x00ff", 1).unwrap();
        assert_eq!(&c[..2], &[0x00, 0x00]);
        assert_eq!(&c[30..], &[0x00, 0xff]);

        let s = parse_const("\"hi\"", 1).unwrap();
        assert_eq!(&s[..2], b"hi");
        assert!(parse_const("0x0", 1).is_err());
        assert!(parse_const("nope", 1).is_err());
        assert!(parse_const(&format!("\"{}\"", "a".repeat(33)), 1).is_err());
    }

    #[test]
    fn hmac_derivation_matches_the_crate() {
        let prog = assemble_bytecode(
            r#"
            .const "eh"
            seed
            push 0
            hmac
            out
            halt
            "#,
        )
        .unwrap();
        let seed = [9u8; 32];
        let out = Vm::with_seed(seed).run(&prog).unwrap();

        let mut msg = [0u8; 32];
        msg[..2].copy_from_slice(b"eh");
        let mut mac = Hmac::<Sha256>::new_from_slice(&seed).unwrap();
        mac.update(&msg);
        assert_eq!(out, mac.finalize().into_bytes().to_vec());
    }

    #[test]
    fn label_jump_skips_code() {
        let prog = assemble_bytecode(
            r#"
            .const 0x01
            .const 0xAA
            push 0          ; nonzero
            jnz end
            push 1          ; skipped
            out
            end:
            seed
            out
            halt
            "#,
        )
        .unwrap();
        let out = Vm::with_seed([7u8; 32]).run(&prog).unwrap();
        assert_eq!(out, vec![7u8; 32]);
    }

    #[test]
    fn relative_jump_skips_code() {
        let prog = assemble_bytecode(
            r#"
            .const 0x01
            .const 0xAA
            push 0
            jnz +4          ; skip "push 1" (2 bytes) and "out" (1 byte)
            push 1
            out
            seed
            out
            halt
            "#,
        )
        .unwrap();
        let out = Vm::with_seed([3u8; 32]).run(&prog).unwrap();
        assert_eq!(out, vec![3u8; 32]);
    }

    #[test]
    fn unknown_label_is_an_error() {
        let e = assemble_bytecode("jnz nope\nhalt").unwrap_err();
        assert_eq!(e.line, 1);
        assert!(e.message.contains("unknown label"));
    }

    #[test]
    fn unknown_mnemonic_is_an_error() {
        let e = assemble_bytecode("frobnicate\nhalt").unwrap_err();
        assert_eq!(e.line, 1);
        assert!(e.message.contains("unknown instruction"));
    }

    #[test]
    fn numeric_operands_accept_hex() {
        assert_eq!(parse_u8("0x0", 1, "slot").unwrap(), 0);
        assert_eq!(parse_u16("0x10", 1, "const index").unwrap(), 16);
        assert_eq!(parse_i64("-0x2", 1, "offset").unwrap(), -2);
        assert_eq!(parse_i64("+0x10", 1, "offset").unwrap(), 16);
        assert!(parse_u8("-1", 1, "slot").is_err());
    }

    #[test]
    fn split_word_handles_multibyte_whitespace() {
        assert_eq!(split_word("push\u{a0}3"), ("push", "3"));
        assert_eq!(split_word("halt"), ("halt", ""));
    }

    #[test]
    fn semicolon_inside_a_string_is_not_a_comment() {
        let prog = assemble_bytecode(".const \"a;b\"\npush 0\nout\nhalt").unwrap();
        let out = Vm::with_seed([0u8; 32]).run(&prog).unwrap();
        assert_eq!(&out[..3], b"a;b");
    }

    #[test]
    fn push_past_the_const_table_is_an_error() {
        let e = assemble_bytecode(".const 0x01\npush 999\nhalt").unwrap_err();
        assert!(e.message.contains("const index"));
    }
}
