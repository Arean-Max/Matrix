#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <memory>
#include <array>

namespace event_horizon::vm {

enum class VMOpcode : uint8_t {
    PUSH_IMM  = 0x01,
    POP       = 0x02,
    DUP       = 0x03,
    SWAP      = 0x04,
    ADD_Q     = 0x10, // Quasigroup Multiply (x * y)
    SUB_Q     = 0x11, // Quasigroup Left Division (x \ y)
    MUL_Q     = 0x12, // Quasigroup Right Division (x / y)
    XOR_Q     = 0x13, // Quasigroup Isotopic S-Box
    JMP       = 0x20,
    JZ        = 0x21,
    LOAD_MEM  = 0x30,
    STORE_MEM = 0x31,
    HALT      = 0xFF
};

class DualEntangledVM {
public:
    static std::unique_ptr<DualEntangledVM> Create();
    virtual ~DualEntangledVM() = default;

    virtual void LoadQuasigroupTable(std::span<const uint8_t, 65536> table) = 0;
    virtual void IngestDynamicDn(std::span<const uint8_t> dn_matrix) = 0;
    virtual bool Execute(std::span<const uint8_t> bytecode,
                         std::span<const uint8_t> input,
                         std::vector<uint8_t>& output,
                         uint64_t& out_state_accumulator) = 0;
    virtual uint64_t GetAccumulator() const = 0;
    virtual void PoisonState(uint64_t perturbation) = 0;
};

} // namespace event_horizon::vm
