use std::error::Error;
use std::fmt;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{MAGIC, MAX_STEPS, WORD};

type HmacSha256 = Hmac<Sha256>;

pub const MEM_SLOTS: usize = 16;
pub const INPUT_SLOTS: usize = 8;

pub mod op {
    pub const HALT: u8 = 0x00;
    pub const PUSH: u8 = 0x01;
    pub const SEED: u8 = 0x02;
    pub const LOAD: u8 = 0x03;
    pub const STORE: u8 = 0x04;
    pub const DUP: u8 = 0x05;
    pub const DROP: u8 = 0x06;
    pub const SWAP: u8 = 0x07;
    pub const XOR: u8 = 0x08;
    pub const ADD: u8 = 0x09;
    pub const SHA: u8 = 0x0A;
    pub const HMAC: u8 = 0x0B;
    pub const CMP: u8 = 0x0C;
    pub const JNZ: u8 = 0x0D;
    pub const OUT: u8 = 0x0E;
    pub const INPUT: u8 = 0x0F;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmError {
    Malformed(&'static str),
    OutOfGas,
    StackUnderflow,
    BadOpcode(u8),
    BadConstIndex(u16),
    BadSlot(u8),
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmError::Malformed(why) => write!(f, "malformed bytecode: {why}"),
            VmError::OutOfGas => write!(f, "step limit exceeded"),
            VmError::StackUnderflow => write!(f, "stack underflow"),
            VmError::BadOpcode(op) => write!(f, "unknown opcode {op:#04x}"),
            VmError::BadConstIndex(i) => write!(f, "const index {i} out of range"),
            VmError::BadSlot(s) => write!(f, "slot {s} out of range"),
        }
    }
}

impl Error for VmError {}

#[derive(Debug, Clone)]
pub struct Bytecode {
    pub consts: Vec<[u8; WORD]>,
    pub code: Vec<u8>,
}

impl Bytecode {
    pub fn parse(bytes: &[u8]) -> Result<Bytecode, VmError> {
        let mut r = Reader::new(bytes);
        if r.take(MAGIC.len())? != MAGIC {
            return Err(VmError::Malformed("bad magic"));
        }
        let count = r.u16()? as usize;
        let mut consts = Vec::with_capacity(count);
        for _ in 0..count {
            let word = r.take(WORD)?;
            let mut c = [0u8; WORD];
            c.copy_from_slice(word);
            consts.push(c);
        }
        let code_len = r.u32()? as usize;
        let code = r.take(code_len)?.to_vec();
        if !r.is_empty() {
            return Err(VmError::Malformed("trailing bytes"));
        }
        Ok(Bytecode { consts, code })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(MAGIC.len() + 2 + self.consts.len() * WORD + 4 + self.code.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.consts.len() as u16).to_be_bytes());
        for c in &self.consts {
            out.extend_from_slice(c);
        }
        out.extend_from_slice(&(self.code.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.code);
        out
    }
}

pub struct Vm {
    seed: [u8; WORD],
    inputs: Vec<[u8; WORD]>,
}

impl Vm {
    pub fn new(seed: [u8; WORD], inputs: Vec<[u8; WORD]>) -> Vm {
        Vm { seed, inputs }
    }

    pub fn with_seed(seed: [u8; WORD]) -> Vm {
        Vm::new(seed, Vec::new())
    }

    pub fn run(&self, prog: &Bytecode) -> Result<Vec<u8>, VmError> {
        let mut stack: Vec<[u8; WORD]> = Vec::with_capacity(64);
        let mut mem = [[0u8; WORD]; MEM_SLOTS];
        let mut out: Vec<u8> = Vec::new();
        let code = &prog.code;
        let mut pc: usize = 0;
        let mut steps: u64 = 0;

        loop {
            steps += 1;
            if steps > MAX_STEPS {
                return Err(VmError::OutOfGas);
            }
            let op = match code.get(pc) {
                Some(op) => *op,
                None => return Err(VmError::Malformed("fell off the end of the code")),
            };
            pc += 1;

            match op {
                op::HALT => break,
                op::PUSH => {
                    let idx = read_u16(code, &mut pc)?;
                    let c = prog
                        .consts
                        .get(idx as usize)
                        .ok_or(VmError::BadConstIndex(idx))?;
                    stack.push(*c);
                }
                op::SEED => stack.push(self.seed),
                op::LOAD => {
                    let slot = read_u8(code, &mut pc)?;
                    let s = mem.get(slot as usize).ok_or(VmError::BadSlot(slot))?;
                    stack.push(*s);
                }
                op::STORE => {
                    let slot = read_u8(code, &mut pc)?;
                    let v = pop(&mut stack)?;
                    let s = mem.get_mut(slot as usize).ok_or(VmError::BadSlot(slot))?;
                    *s = v;
                }
                op::DUP => {
                    let v = *stack.last().ok_or(VmError::StackUnderflow)?;
                    stack.push(v);
                }
                op::DROP => {
                    pop(&mut stack)?;
                }
                op::SWAP => {
                    let b = pop(&mut stack)?;
                    let a = pop(&mut stack)?;
                    stack.push(b);
                    stack.push(a);
                }
                op::XOR => {
                    let b = pop(&mut stack)?;
                    let a = pop(&mut stack)?;
                    let mut r = [0u8; WORD];
                    for i in 0..WORD {
                        r[i] = a[i] ^ b[i];
                    }
                    stack.push(r);
                }
                op::ADD => {
                    let b = pop(&mut stack)?;
                    let a = pop(&mut stack)?;
                    let mut r = [0u8; WORD];
                    let mut carry = 0u16;
                    for i in (0..WORD).rev() {
                        let v = a[i] as u16 + b[i] as u16 + carry;
                        r[i] = v as u8;
                        carry = v >> 8;
                    }
                    stack.push(r);
                }
                op::SHA => {
                    let a = pop(&mut stack)?;
                    let mut h = Sha256::new();
                    h.update(a);
                    let digest = h.finalize();
                    let mut r = [0u8; WORD];
                    r.copy_from_slice(&digest);
                    stack.push(r);
                }
                op::HMAC => {
                    let msg = pop(&mut stack)?;
                    let key = pop(&mut stack)?;
                    let mut mac = HmacSha256::new_from_slice(&key)
                        .map_err(|_| VmError::Malformed("hmac key"))?;
                    mac.update(&msg);
                    let digest = mac.finalize().into_bytes();
                    let mut r = [0u8; WORD];
                    r.copy_from_slice(&digest);
                    stack.push(r);
                }
                op::CMP => {
                    let b = pop(&mut stack)?;
                    let a = pop(&mut stack)?;
                    let r = if a == b { [0xFFu8; WORD] } else { [0u8; WORD] };
                    stack.push(r);
                }
                op::JNZ => {
                    let off = read_i16(code, &mut pc)?;
                    let target = pc as i64 + off as i64;
                    if target < 0 || target as usize > code.len() {
                        return Err(VmError::Malformed("jump out of range"));
                    }
                    let v = pop(&mut stack)?;
                    if v.iter().any(|&b| b != 0) {
                        pc = target as usize;
                    }
                }
                op::OUT => {
                    let v = pop(&mut stack)?;
                    out.extend_from_slice(&v);
                }
                op::INPUT => {
                    let slot = read_u8(code, &mut pc)?;
                    if slot as usize >= INPUT_SLOTS {
                        return Err(VmError::BadSlot(slot));
                    }
                    let v = self
                        .inputs
                        .get(slot as usize)
                        .copied()
                        .unwrap_or([0u8; WORD]);
                    stack.push(v);
                }
                other => return Err(VmError::BadOpcode(other)),
            }
        }
        Ok(out)
    }
}

fn pop(stack: &mut Vec<[u8; WORD]>) -> Result<[u8; WORD], VmError> {
    stack.pop().ok_or(VmError::StackUnderflow)
}

fn read_u8(code: &[u8], pc: &mut usize) -> Result<u8, VmError> {
    let b = *code
        .get(*pc)
        .ok_or(VmError::Malformed("truncated immediate"))?;
    *pc += 1;
    Ok(b)
}

fn read_u16(code: &[u8], pc: &mut usize) -> Result<u16, VmError> {
    let hi = read_u8(code, pc)? as u16;
    let lo = read_u8(code, pc)? as u16;
    Ok((hi << 8) | lo)
}

fn read_i16(code: &[u8], pc: &mut usize) -> Result<i16, VmError> {
    Ok(read_u16(code, pc)? as i16)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], VmError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(VmError::Malformed("length overflow"))?;
        if end > self.buf.len() {
            return Err(VmError::Malformed("truncated bytecode"));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u16(&mut self) -> Result<u16, VmError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, VmError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asm::assemble_bytecode;

    #[test]
    fn binary_round_trip() {
        let prog = assemble_bytecode(".const \"a\"\nseed\nout\nhalt").unwrap();
        let bytes = prog.to_bytes();
        let back = Bytecode::parse(&bytes).unwrap();
        assert_eq!(back.consts, prog.consts);
        assert_eq!(back.code, prog.code);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(Bytecode::parse(b"nope").is_err());
        let mut bytes = assemble_bytecode("halt").unwrap().to_bytes();
        bytes.push(0);
        assert!(matches!(
            Bytecode::parse(&bytes),
            Err(VmError::Malformed("trailing bytes"))
        ));
        assert!(Bytecode::parse(&bytes[..bytes.len() - 2]).is_err());
    }

    #[test]
    fn stack_underflow() {
        let prog = assemble_bytecode("xor\nhalt").unwrap();
        assert_eq!(
            Vm::with_seed([0u8; 32]).run(&prog),
            Err(VmError::StackUnderflow)
        );
    }

    #[test]
    fn out_of_gas() {
        let prog = assemble_bytecode(
            r#"
            .const 0x01
            loop:
            push 0
            jnz loop
            halt
            "#,
        )
        .unwrap();
        assert_eq!(Vm::with_seed([0u8; 32]).run(&prog), Err(VmError::OutOfGas));
    }

    #[test]
    fn inputs_and_memory() {
        let prog = assemble_bytecode(
            r#"
            input 0
            store 0
            load 0
            out
            input 7       ; unset input reads as zero
            out
            halt
            "#,
        )
        .unwrap();
        let vm = Vm::new([1u8; 32], vec![[5u8; 32]]);
        let out = vm.run(&prog).unwrap();
        assert_eq!(&out[..32], &[5u8; 32]);
        assert_eq!(&out[32..], &[0u8; 32]);
    }

    #[test]
    fn arithmetic_is_big_endian_mod_2_256() {
        let prog = assemble_bytecode(
            r#"
            .const 0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            .const 0x01
            push 0
            push 1
            add
            out
            halt
            "#,
        )
        .unwrap();
        let out = Vm::with_seed([0u8; 32]).run(&prog).unwrap();
        let mut want = [0u8; 32];
        want[0] = 0x01;
        assert_eq!(out, want.to_vec());
    }

    #[test]
    fn doc_examples_run_as_documented() {
        let prog = assemble_bytecode(
            r#"
            seed
            .const "asset-key/v1"
            push 0
            hmac
            out
            halt
            "#,
        )
        .unwrap();
        let seed = [7u8; 32];
        let out = Vm::with_seed(seed).run(&prog).unwrap();
        let mut label = [0u8; 32];
        label[..12].copy_from_slice(b"asset-key/v1");
        let mut mac = HmacSha256::new_from_slice(&seed).unwrap();
        mac.update(&label);
        assert_eq!(out, mac.finalize().into_bytes().to_vec());

        let prog = assemble_bytecode(
            r#"
            .const 0x01
            push 0
            push 0
            cmp
            jnz hit
            .const "no"
            push 1
            out
            halt
            hit:
            .const "yes"
            push 2
            out
            halt
            "#,
        )
        .unwrap();
        let out = Vm::with_seed([0u8; 32]).run(&prog).unwrap();
        let mut want = [0u8; 32];
        want[..3].copy_from_slice(b"yes");
        assert_eq!(out, want.to_vec());
    }
}
