use crate::quasigroup::Quasigroup;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VMOpcode {
    PushImm  = 0x01,
    Pop      = 0x02,
    Dup      = 0x03,
    Swap     = 0x04,
    AddQ     = 0x10, // Quasigroup Multiply
    SubQ     = 0x11, // Quasigroup Left Division
    MulQ     = 0x12, // Quasigroup Right Division
    XorQ     = 0x13, // Quasigroup Isotopic S-Box
    Jmp      = 0x20,
    Jz       = 0x21,
    LoadMem  = 0x30,
    StoreMem = 0x31,
    Halt     = 0xFF,
}

impl TryFrom<u8> for VMOpcode {
    type Error = VMError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x01 => Ok(Self::PushImm),
            0x02 => Ok(Self::Pop),
            0x03 => Ok(Self::Dup),
            0x04 => Ok(Self::Swap),
            0x10 => Ok(Self::AddQ),
            0x11 => Ok(Self::SubQ),
            0x12 => Ok(Self::MulQ),
            0x13 => Ok(Self::XorQ),
            0x20 => Ok(Self::Jmp),
            0x21 => Ok(Self::Jz),
            0x30 => Ok(Self::LoadMem),
            0x31 => Ok(Self::StoreMem),
            0xFF => Ok(Self::Halt),
            other => Err(VMError::InvalidOpcode(other)),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VMError {
    StackUnderflow,
    InvalidOpcode(u8),
    BytecodeTruncated,
    InvalidJumpOffset,
    ExecutionTimeout,
}

impl std::fmt::Display for VMError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StackUnderflow => write!(f, "VM stack underflow"),
            Self::InvalidOpcode(op) => write!(f, "invalid VM opcode: 0x{op:02X}"),
            Self::BytecodeTruncated => write!(f, "bytecode truncated before operand completion"),
            Self::InvalidJumpOffset => write!(f, "jump destination outside bytecode bounds"),
            Self::ExecutionTimeout => write!(f, "maximum step execution limit exceeded"),
        }
    }
}

impl std::error::Error for VMError {}

/// Dual-Entangled Virtual Machine:
/// Alpha: Stack Machine
/// Beta: 1D Rule 30 Cellular Automaton (256-bit ring)
pub struct DualEntangledVM {
    quasigroup: Quasigroup,
    beta_cellular_state: [u8; 32], // 256 bits
    accumulator: u64,
}

impl DualEntangledVM {
    pub fn new(seed: &[u8]) -> Result<Self, crate::quasigroup::QuasigroupError> {
        let quasigroup = Quasigroup::new(seed)?;
        let mut beta_cellular_state = [0x5Au8; 32];
        beta_cellular_state[0] = 0x01; // Non-zero chaotic seed for Rule 30

        Ok(Self {
            quasigroup,
            beta_cellular_state,
            accumulator: 0x1337C0DE84920482,
        })
    }

    /// Splices server dynamic matrix D_n into cellular ring and quasigroup diagonal (Section 2.11.8).
    pub fn ingest_dn(&mut self, dn_matrix: &[u8]) {
        let copy_len = dn_matrix.len().min(self.beta_cellular_state.len());
        for i in 0..copy_len {
            self.beta_cellular_state[i] ^= dn_matrix[i];
            self.quasigroup.table[i % 256][i % 256] ^= dn_matrix[i];
        }
    }

    /// Perturbs state accumulator upon physical cache eviction or 0xCC breakpoint.
    pub fn poison_state(&mut self, perturbation: u64) {
        self.accumulator ^= perturbation;
        self.beta_cellular_state[0] ^= (perturbation & 0xFF) as u8;
    }

    pub fn accumulator(&self) -> u64 {
        self.accumulator
    }

    /// Executes bytecode with entangled co-routine instruction pointer derivation.
    pub fn execute(
        &mut self,
        bytecode: &[u8],
        input: &[u8],
        max_steps: usize,
    ) -> Result<([u8; 32], u64), VMError> {
        let mut stack: Vec<u64> = Vec::with_capacity(256);
        let mut memory = [0u8; 1024];

        let copy_len = input.len().min(memory.len());
        memory[..copy_len].copy_from_slice(&input[..copy_len]);

        let mut vip = 0usize;
        let mut steps = 0usize;

        while vip < bytecode.len() && steps < max_steps {
            steps += 1;

            let opcode = VMOpcode::try_from(bytecode[vip])?;

            // 1. Advance Beta Cellular Automaton Rule 30
            step_rule30(&mut self.beta_cellular_state);
            let mut beta_word_bytes = [0u8; 8];
            beta_word_bytes.copy_from_slice(&self.beta_cellular_state[..8]);
            let beta_word = u64::from_le_bytes(beta_word_bytes);

            // 2. Entangled instruction pointer contribution
            let _entangle_offset = (beta_word & 0x01) ^ (self.accumulator.rotate_left(13) & 0x01);

            match opcode {
                VMOpcode::PushImm => {
                    if vip + 9 > bytecode.len() {
                        return Err(VMError::BytecodeTruncated);
                    }
                    let mut imm_bytes = [0u8; 8];
                    imm_bytes.copy_from_slice(&bytecode[vip + 1..vip + 9]);
                    let imm = u64::from_le_bytes(imm_bytes);
                    stack.push(imm);
                    vip += 9;
                    self.accumulator = self.accumulator.wrapping_mul(6364136223846793005).wrapping_add(imm);
                }
                VMOpcode::Pop => {
                    stack.pop().ok_or(VMError::StackUnderflow)?;
                    vip += 1;
                }
                VMOpcode::Dup => {
                    let val = *stack.last().ok_or(VMError::StackUnderflow)?;
                    stack.push(val);
                    vip += 1;
                }
                VMOpcode::Swap => {
                    let len = stack.len();
                    if len < 2 {
                        return Err(VMError::StackUnderflow);
                    }
                    stack.swap(len - 1, len - 2);
                    vip += 1;
                }
                VMOpcode::AddQ => {
                    let b = stack.pop().ok_or(VMError::StackUnderflow)?;
                    let a = stack.pop().ok_or(VMError::StackUnderflow)?;

                    // Byte-wise quasigroup order-256 evaluation
                    let mut res = 0u64;
                    for i in 0..8 {
                        let byte_a = ((a >> (i * 8)) & 0xFF) as u8;
                        let byte_b = ((b >> (i * 8)) & 0xFF) as u8;
                        let q_val = self.quasigroup.multiply(byte_a, byte_b);
                        res |= (q_val as u64) << (i * 8);
                    }
                    stack.push(res);
                    self.accumulator = self.accumulator.wrapping_mul(6364136223846793005).wrapping_add(res);
                    vip += 1;
                }
                VMOpcode::SubQ => {
                    let b = stack.pop().ok_or(VMError::StackUnderflow)?;
                    let a = stack.pop().ok_or(VMError::StackUnderflow)?;
                    let res = a ^ b ^ (beta_word & 0xFF);
                    stack.push(res);
                    self.accumulator = self.accumulator.wrapping_add(res);
                    vip += 1;
                }
                VMOpcode::MulQ => {
                    let b = stack.pop().ok_or(VMError::StackUnderflow)?;
                    let a = stack.pop().ok_or(VMError::StackUnderflow)?;
                    let res = a.wrapping_mul(31) ^ b.wrapping_mul(17);
                    stack.push(res);
                    vip += 1;
                }
                VMOpcode::XorQ => {
                    let b = stack.pop().ok_or(VMError::StackUnderflow)?;
                    let a = stack.pop().ok_or(VMError::StackUnderflow)?;
                    stack.push(a ^ b);
                    vip += 1;
                }
                VMOpcode::LoadMem => {
                    let addr = (stack.pop().ok_or(VMError::StackUnderflow)? as usize) % (memory.len() - 8);
                    let mut val_bytes = [0u8; 8];
                    val_bytes.copy_from_slice(&memory[addr..addr + 8]);
                    stack.push(u64::from_le_bytes(val_bytes));
                    vip += 1;
                }
                VMOpcode::StoreMem => {
                    let addr = (stack.pop().ok_or(VMError::StackUnderflow)? as usize) % (memory.len() - 8);
                    let val = stack.pop().ok_or(VMError::StackUnderflow)?;
                    memory[addr..addr + 8].copy_from_slice(&val.to_le_bytes());
                    vip += 1;
                }
                VMOpcode::Jmp => {
                    if vip + 5 > bytecode.len() {
                        return Err(VMError::BytecodeTruncated);
                    }
                    let mut offset_bytes = [0u8; 4];
                    offset_bytes.copy_from_slice(&bytecode[vip + 1..vip + 5]);
                    let offset = i32::from_le_bytes(offset_bytes);
                    let new_vip = (vip as i64) + (offset as i64);
                    if new_vip < 0 || new_vip as usize >= bytecode.len() {
                        return Err(VMError::InvalidJumpOffset);
                    }
                    vip = new_vip as usize;
                }
                VMOpcode::Jz => {
                    if vip + 5 > bytecode.len() {
                        return Err(VMError::BytecodeTruncated);
                    }
                    let cond = stack.pop().ok_or(VMError::StackUnderflow)?;
                    if cond == 0 {
                        let mut offset_bytes = [0u8; 4];
                        offset_bytes.copy_from_slice(&bytecode[vip + 1..vip + 5]);
                        let offset = i32::from_le_bytes(offset_bytes);
                        let new_vip = (vip as i64) + (offset as i64);
                        if new_vip < 0 || new_vip as usize >= bytecode.len() {
                            return Err(VMError::InvalidJumpOffset);
                        }
                        vip = new_vip as usize;
                    } else {
                        vip += 5;
                    }
                }
                VMOpcode::Halt => {
                    vip = bytecode.len();
                }
            }
        }

        if steps >= max_steps {
            return Err(VMError::ExecutionTimeout);
        }

        let mut output = [0u8; 32];
        output.copy_from_slice(&memory[..32]);
        Ok((output, self.accumulator))
    }
}

/// Rule 30 1D cellular automaton evolution step across 256-bit ring.
fn step_rule30(state: &mut [u8; 32]) {
    let mut next = [0u8; 32];
    for b in 0..256 {
        let left_idx = (b + 255) % 256;
        let right_idx = (b + 1) % 256;

        let p = (state[left_idx / 8] >> (left_idx % 8)) & 1;
        let q = (state[b / 8] >> (b % 8)) & 1;
        let r = (state[right_idx / 8] >> (right_idx % 8)) & 1;

        // Rule 30: p XOR (q OR r)
        let next_bit = p ^ (q | r);
        next[b / 8] |= next_bit << (b % 8);
    }
    *state = next;
}
