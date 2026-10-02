#include "dual_vm.h"
#include "../../include/event_horizon_core.h"

#include <vector>
#include <memory>
#include <iostream>

namespace event_horizon::vm {

class DualEntangledVMRustImpl final : public DualEntangledVM {
public:
    DualEntangledVMRustImpl() {
        uint8_t seed[32]{};
        for (size_t i = 0; i < sizeof(seed); ++i) {
            seed[i] = static_cast<uint8_t>((i * 73) ^ 0xA5);
        }
        rustVm_ = eh_vm_create(seed, sizeof(seed));
    }

    ~DualEntangledVMRustImpl() override {
        if (rustVm_) {
            eh_vm_destroy(rustVm_);
            rustVm_ = nullptr;
        }
    }

    void LoadQuasigroupTable(std::span<const uint8_t, 65536> table) override {
        // Table is managed internally within safe Rust Quasigroup struct
        (void)table;
    }

    void IngestDynamicDn(std::span<const uint8_t> dn_matrix) override {
        if (rustVm_ && !dn_matrix.empty()) {
            eh_vm_ingest_dn(rustVm_, dn_matrix.data(), dn_matrix.size());
        }
    }

    void PoisonState(uint64_t perturbation) override {
        if (rustVm_) {
            eh_vm_poison(rustVm_, perturbation);
        }
        accumulator_ ^= perturbation;
    }

    uint64_t GetAccumulator() const override {
        return accumulator_;
    }

    bool Execute(std::span<const uint8_t> bytecode,
                 std::span<const uint8_t> input,
                 std::vector<uint8_t>& output,
                 uint64_t& out_state_accumulator) override {
        if (!rustVm_ || bytecode.empty()) {
            return false;
        }

        output.resize(32);
        uint64_t acc = 0;
        int32_t rc = eh_vm_execute(
            rustVm_,
            bytecode.data(),
            bytecode.size(),
            input.data(),
            input.size(),
            output.data(),
            &acc
        );

        if (rc != 0) {
            return false;
        }

        accumulator_ = acc;
        out_state_accumulator = acc;
        return true;
    }

private:
    EH_DualEntangledVM* rustVm_ = nullptr;
    uint64_t accumulator_ = 0x1337C0DE84920482ULL;
};

#ifdef USE_RUST_CORE
std::unique_ptr<DualEntangledVM> DualEntangledVM::Create() {
    return std::make_unique<DualEntangledVMRustImpl>();
}
#endif

std::unique_ptr<DualEntangledVM> CreateRustVM() {
    return std::make_unique<DualEntangledVMRustImpl>();
}

} // namespace event_horizon::vm
