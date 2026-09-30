use crate::quasigroup::Quasigroup;
use crate::whitebox::{WhiteBoxNetwork, BLOCK_SIZE};
use crate::dual_vm::DualEntangledVM;

#[no_mangle]
pub unsafe extern "C" fn eh_quasigroup_create(seed: *const u8, seed_len: usize) -> *mut Quasigroup {
    if seed.is_null() || seed_len == 0 {
        return std::ptr::null_mut();
    }
    let slice = std::slice::from_raw_parts(seed, seed_len);
    match Quasigroup::new(slice) {
        Ok(q) => Box::into_raw(Box::new(q)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn eh_quasigroup_multiply(q: *const Quasigroup, x: u8, y: u8) -> u8 {
    if q.is_null() {
        return 0;
    }
    (*q).multiply(x, y)
}

#[no_mangle]
pub unsafe extern "C" fn eh_quasigroup_destroy(q: *mut Quasigroup) {
    if !q.is_null() {
        drop(Box::from_raw(q));
    }
}

#[no_mangle]
pub unsafe extern "C" fn eh_whitebox_create(key: *const u8, key_len: usize) -> *mut WhiteBoxNetwork {
    if key.is_null() || key_len != 32 {
        return std::ptr::null_mut();
    }
    let slice = std::slice::from_raw_parts(key, key_len);
    match WhiteBoxNetwork::new(slice) {
        Ok(wb) => Box::into_raw(Box::new(wb)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn eh_whitebox_transform_block(
    wb: *const WhiteBoxNetwork,
    in_block: *const u8,
    out_block: *mut u8,
) -> i32 {
    if wb.is_null() || in_block.is_null() || out_block.is_null() {
        return -1;
    }
    let mut block = [0u8; BLOCK_SIZE];
    std::ptr::copy_nonoverlapping(in_block, block.as_mut_ptr(), BLOCK_SIZE);
    let transformed = (*wb).transform_block(&block);
    std::ptr::copy_nonoverlapping(transformed.as_ptr(), out_block, BLOCK_SIZE);
    0
}

#[no_mangle]
pub unsafe extern "C" fn eh_whitebox_destroy(wb: *mut WhiteBoxNetwork) {
    if !wb.is_null() {
        drop(Box::from_raw(wb));
    }
}

#[no_mangle]
pub unsafe extern "C" fn eh_vm_create(seed: *const u8, seed_len: usize) -> *mut DualEntangledVM {
    if seed.is_null() || seed_len == 0 {
        return std::ptr::null_mut();
    }
    let slice = std::slice::from_raw_parts(seed, seed_len);
    match DualEntangledVM::new(slice) {
        Ok(vm) => Box::into_raw(Box::new(vm)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn eh_vm_execute(
    vm: *mut DualEntangledVM,
    bytecode: *const u8,
    bytecode_len: usize,
    input: *const u8,
    input_len: usize,
    out_output: *mut u8,
    out_acc: *mut u64,
) -> i32 {
    if vm.is_null() || bytecode.is_null() || bytecode_len == 0 || out_output.is_null() || out_acc.is_null() {
        return -1;
    }
    let code = std::slice::from_raw_parts(bytecode, bytecode_len);
    let inp = if input.is_null() || input_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(input, input_len)
    };

    match (*vm).execute(code, inp, 100_000) {
        Ok((out_buf, acc)) => {
            std::ptr::copy_nonoverlapping(out_buf.as_ptr(), out_output, 32);
            *out_acc = acc;
            0
        }
        Err(_) => -2,
    }
}

#[no_mangle]
pub unsafe extern "C" fn eh_vm_ingest_dn(vm: *mut DualEntangledVM, dn: *const u8, dn_len: usize) {
    if !vm.is_null() && !dn.is_null() && dn_len > 0 {
        let slice = std::slice::from_raw_parts(dn, dn_len);
        (*vm).ingest_dn(slice);
    }
}

#[no_mangle]
pub unsafe extern "C" fn eh_vm_poison(vm: *mut DualEntangledVM, perturbation: u64) {
    if !vm.is_null() {
        (*vm).poison_state(perturbation);
    }
}

#[no_mangle]
pub unsafe extern "C" fn eh_vm_destroy(vm: *mut DualEntangledVM) {
    if !vm.is_null() {
        drop(Box::from_raw(vm));
    }
}
