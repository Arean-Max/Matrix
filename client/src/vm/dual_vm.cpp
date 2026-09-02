#include "dual_vm.h"

#include <vector>
#include <array>
#include <bit>
#include <cstring>
#include <stdexcept>

namespace event_horizon::vm {

namespace {

inline uint64_t RotL64(uint64_t x, int s) {
    return (x << s) | (x >> (64 - s));
}

// Rule 30 1D cellular automaton step on 256-bit ring
void StepRule30(std::array<uint8_t, 32>& state) {
    std::array<uint8_t, 32> next{};
    for (size_t b = 0; b < 256; ++b) {
        size_t leftIdx = (b + 255) % 256;
        size_t rightIdx = (b + 1) % 256;

        uint8_t p = (state[leftIdx / 8] >> (leftIdx % 8)) & 1;
        uint8_t q = (state[b / 8] >> (b % 8)) & 1;
        uint8_t r = (state[rightIdx / 8] >> (rightIdx % 8)) & 1;

        // Rule 30: p XOR (q OR r)
        uint8_t nextBit = p ^ (q | r);
        next[b / 8] |= (nextBit << (b % 8));
    }
    state = next;
}

} // namespace

class DualEntangledVMImpl final : public DualEntangledVM {
public:
    DualEntangledVMImpl() {
        // Initialize default quasigroup Latin square
        for (int r = 0; r < 256; ++r) {
            for (int c = 0; c < 256; ++c) {
                quasigroupTable_[r][c] = static_cast<uint8_t>((r * 131 + c * 73 + 0x55) & 0xFF);
            }
        }
        betaCellularState_.fill(0x5A);
        betaCellularState_[0] = 0x01; // Non-zero seed for Rule 30 chaos
    }

    void LoadQuasigroupTable(std::span<const uint8_t, 65536> table) override {
        for (int r = 0; r < 256; ++r) {
            std::memcpy(quasigroupTable_[r].data(), table.data() + (r * 256), 256);
        }
    }

    void IngestDynamicDn(std::span<const uint8_t> dn_matrix) override {
        // Splice server dynamic matrix into cellular ring and quasigroup diagonal
        size_t copyLen = (std::min)(dn_matrix.size(), betaCellularState_.size());
        for (size_t i = 0; i < copyLen; ++i) {
            betaCellularState_[i] ^= dn_matrix[i];
            quasigroupTable_[i % 256][i % 256] ^= dn_matrix[i];
        }
    }

    void PoisonState(uint64_t perturbation) override {
        accumulator_ ^= perturbation;
        betaCellularState_[0] ^= static_cast<uint8_t>(perturbation & 0xFF);
    }

    uint64_t GetAccumulator() const override {
        return accumulator_;
    }

    bool Execute(std::span<const uint8_t> bytecode,
                 std::span<const uint8_t> input,
                 std::vector<uint8_t>& output,
                 uint64_t& out_state_accumulator) override {
        std::vector<uint64_t> stack;
        stack.reserve(256);
        std::array<uint8_t, 1024> memory{};
        size_t inputCopy = (std::min)(input.size(), memory.size());
        std::copy_n(input.begin(), inputCopy, memory.begin());

        size_t vip = 0;
        size_t steps = 0;
        constexpr size_t MaxSteps = 100000;

        while (vip < bytecode.size() && steps++ < MaxSteps) {
            uint8_t rawOp = bytecode[vip];
            auto op = static_cast<VMOpcode>(rawOp);

            // 1. Advance Beta Cellular Automaton
            StepRule30(betaCellularState_);
            uint64_t betaWord = 0;
            std::memcpy(&betaWord, betaCellularState_.data(), sizeof(betaWord));

            // Entangled delta computation
            uint64_t entangleOffset = (betaWord & 0x01) ^ (RotL64(accumulator_, 13) & 0x01);

            switch (op) {
                case VMOpcode::PUSH_IMM: {
                    if (vip + 8 >= bytecode.size()) return false;
                    uint64_t imm = 0;
                    std::memcpy(&imm, &bytecode[vip + 1], 8);
                    stack.push_back(imm);
                    vip += 9;
                    accumulator_ = (accumulator_ * 6364136223846793005ULL) + imm;
                    break;
                }
                case VMOpcode::POP: {
                    if (stack.empty()) return false;
                    stack.pop_back();
                    vip += 1;
                    break;
                }
                case VMOpcode::DUP: {
                    if (stack.empty()) return false;
                    stack.push_back(stack.back());
                    vip += 1;
                    break;
                }
                case VMOpcode::SWAP: {
                    if (stack.size() < 2) return false;
                    std::swap(stack[stack.size() - 1], stack[stack.size() - 2]);
                    vip += 1;
                    break;
                }
                case VMOpcode::ADD_Q: { // Quasigroup Multiply
                    if (stack.size() < 2) return false;
                    uint64_t b = stack.back(); stack.pop_back();
                    uint64_t a = stack.back(); stack.pop_back();

                    // Evaluate quasigroup order-256 byte-wise
                    uint64_t res = 0;
                    for (int i = 0; i < 8; ++i) {
                        uint8_t byteA = (a >> (i * 8)) & 0xFF;
                        uint8_t byteB = (b >> (i * 8)) & 0xFF;
                        uint8_t qVal = quasigroupTable_[byteA][byteB];
                        res |= (static_cast<uint64_t>(qVal) << (i * 8));
                    }
                    stack.push_back(res);
                    accumulator_ = (accumulator_ * 6364136223846793005ULL) + res;
                    vip += 1;
                    break;
                }
                case VMOpcode::SUB_Q: {
                    if (stack.size() < 2) return false;
                    uint64_t b = stack.back(); stack.pop_back();
                    uint64_t a = stack.back(); stack.pop_back();
                    uint64_t res = a ^ b ^ (betaWord & 0xFF);
                    stack.push_back(res);
                    accumulator_ += res;
                    vip += 1;
                    break;
                }
                case VMOpcode::MUL_Q: {
                    if (stack.size() < 2) return false;
                    uint64_t b = stack.back(); stack.pop_back();
                    uint64_t a = stack.back(); stack.pop_back();
                    uint64_t res = (a * 31) ^ (b * 17);
                    stack.push_back(res);
                    vip += 1;
                    break;
                }
                case VMOpcode::XOR_Q: {
                    if (stack.size() < 2) return false;
                    uint64_t b = stack.back(); stack.pop_back();
                    uint64_t a = stack.back(); stack.pop_back();
                    uint64_t res = a ^ b;
                    stack.push_back(res);
                    vip += 1;
                    break;
                }
                case VMOpcode::LOAD_MEM: {
                    if (stack.empty()) return false;
                    uint64_t addr = stack.back() % (memory.size() - 8);
                    stack.pop_back();
                    uint64_t val = 0;
                    std::memcpy(&val, &memory[addr], 8);
                    stack.push_back(val);
                    vip += 1;
                    break;
                }
                case VMOpcode::STORE_MEM: {
                    if (stack.size() < 2) return false;
                    uint64_t addr = stack.back() % (memory.size() - 8);
                    stack.pop_back();
                    uint64_t val = stack.back();
                    stack.pop_back();
                    std::memcpy(&memory[addr], &val, 8);
                    vip += 1;
                    break;
                }
                case VMOpcode::JMP: {
                    if (vip + 4 >= bytecode.size()) return false;
                    int32_t offset = 0;
                    std::memcpy(&offset, &bytecode[vip + 1], 4);
                    vip = static_cast<size_t>(static_cast<int64_t>(vip) + offset);
                    break;
                }
                case VMOpcode::JZ: {
                    if (stack.empty() || vip + 4 >= bytecode.size()) return false;
                    uint64_t cond = stack.back();
                    stack.pop_back();
                    if (cond == 0) {
                        int32_t offset = 0;
                        std::memcpy(&offset, &bytecode[vip + 1], 4);
                        vip = static_cast<size_t>(static_cast<int64_t>(vip) + offset);
                    } else {
                        vip += 5;
                    }
                    break;
                }
                case VMOpcode::HALT: {
                    vip = bytecode.size();
                    break;
                }
                default:
                    // Unknown opcode: chaotic drift
                    accumulator_ ^= 0xDEADBEEF;
                    return false;
            }
        }

        output.assign(memory.begin(), memory.begin() + 32);
        out_state_accumulator = accumulator_;
        return true;
    }

private:
    std::array<std::array<uint8_t, 256>, 256> quasigroupTable_{};
    std::array<uint8_t, 32> betaCellularState_{};
    uint64_t accumulator_ = 0x1337C0DE84920482ULL;
};

std::unique_ptr<DualEntangledVM> DualEntangledVM::Create() {
    return std::make_unique<DualEntangledVMImpl>();
}

} // namespace event_horizon::vm
