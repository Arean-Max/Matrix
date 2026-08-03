pub mod asm;
pub mod vm;

pub use asm::{assemble, AsmError};
pub use vm::{Bytecode, Vm, VmError};

pub const MAGIC: &[u8; 5] = b"EHVM1";
pub const WORD: usize = 32;
pub const MAX_STEPS: u64 = 1_000_000;
