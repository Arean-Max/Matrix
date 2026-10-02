#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handles prefixed with EH_ to prevent C++ namespace collision
typedef struct EH_Quasigroup EH_Quasigroup;
typedef struct EH_WhiteBoxNetwork EH_WhiteBoxNetwork;
typedef struct EH_DualEntangledVM EH_DualEntangledVM;

// Quasigroup API
EH_Quasigroup* eh_quasigroup_create(const uint8_t* seed, size_t seed_len);
uint8_t eh_quasigroup_multiply(const EH_Quasigroup* q, uint8_t x, uint8_t y);
void eh_quasigroup_destroy(EH_Quasigroup* q);

// White-Box API
EH_WhiteBoxNetwork* eh_whitebox_create(const uint8_t* key, size_t key_len);
int32_t eh_whitebox_transform_block(const EH_WhiteBoxNetwork* wb, const uint8_t* in_block, uint8_t* out_block);
void eh_whitebox_destroy(EH_WhiteBoxNetwork* wb);

// Dual-Entangled VM API
EH_DualEntangledVM* eh_vm_create(const uint8_t* seed, size_t seed_len);
int32_t eh_vm_execute(
    EH_DualEntangledVM* vm,
    const uint8_t* bytecode,
    size_t bytecode_len,
    const uint8_t* input,
    size_t input_len,
    uint8_t* out_output,
    uint64_t* out_acc
);
void eh_vm_ingest_dn(EH_DualEntangledVM* vm, const uint8_t* dn, size_t dn_len);
void eh_vm_poison(EH_DualEntangledVM* vm, uint64_t perturbation);
void eh_vm_destroy(EH_DualEntangledVM* vm);

#ifdef __cplusplus
}
#endif
