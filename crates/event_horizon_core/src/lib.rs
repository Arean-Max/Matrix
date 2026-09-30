pub mod quasigroup;
pub mod whitebox;
pub mod dual_vm;
pub mod ffi;

pub use quasigroup::{Quasigroup, QuasigroupError};
pub use whitebox::{WhiteBoxNetwork, WhiteBoxError};
pub use dual_vm::{DualEntangledVM, VMError, VMOpcode};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quasigroup_properties() {
        let seed = b"event-horizon-rust-seed-1";
        let q = Quasigroup::new(seed).expect("quasigroup generation should succeed");
        assert!(q.validate_latin_square().is_ok());
        assert!(q.verify_non_associativity());

        // Test Latin square Cayley inverses
        let x = 42u8;
        let y = 105u8;
        let z = q.multiply(x, y);
        assert_eq!(q.left_div(x, z), y);
        assert_eq!(q.right_div(z, y), x);
    }

    #[test]
    fn test_whitebox_transform() {
        let key = [0x42u8; 32];
        let wb = WhiteBoxNetwork::new(&key).expect("whitebox generation should succeed");

        let block = *b"0123456789abcdef";
        let transformed = wb.transform_block(&block);
        assert_eq!(transformed.len(), 16);

        // Determinism test
        let transformed2 = wb.transform_block(&block);
        assert_eq!(transformed, transformed2);
    }

    #[test]
    fn test_dual_vm_execution() {
        let seed = b"vm-seed-rust-core";
        let mut vm = DualEntangledVM::new(seed).expect("vm initialization should succeed");

        // PUSH_IMM 1, PUSH_IMM 2, ADD_Q, HALT
        let bytecode = [
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x10,
            0xFF,
        ];

        let input = [0x55u8; 16];
        let (output, acc) = vm.execute(&bytecode, &input, 1000).expect("vm execution should succeed");
        assert_eq!(output.len(), 32);
        assert_ne!(acc, 0);
    }
}
