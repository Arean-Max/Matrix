#include "chaff_machine.h"

#include <cstring>
#include <format>
#include <string_view>

namespace event_horizon::vm {

namespace {

constexpr std::string_view DecoyJSONResponse =
    R"({"status":"OK","license_state":"ACTIVE","tier":"ENTERPRISE_UNRESTRICTED","hwid_verified":true})";

// Plausible fake cryptographic key schedule (looks legitimate in x64dbg memory view)
alignas(16) const uint8_t FakeDecoyKey[32] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x3c, 0x4f, 0xcf, 0x09, 0x88, 0x15, 0xf7, 0xab,
    0xa6, 0xd2, 0xae, 0x28, 0x16, 0x15, 0x7e, 0x2b
};

} // namespace

ChaffStateMachine::ChaffStateMachine() = default;

bool ChaffStateMachine::IsPoisoned(uint64_t current_accumulator, uint64_t expected_accumulator) const {
    // Constant-time difference check
    uint64_t diff = current_accumulator ^ expected_accumulator;
    return diff != 0;
}

DecoyOutput ChaffStateMachine::ExecuteDecoyRoutine(std::span<const uint8_t> input) {
    DecoyOutput out{};
    out.status_code = 0; // STATUS_SUCCESS (no error popups, process continues uninterrupted)
    out.honeypot_flag = true;

    // Construct plausible output buffer embedding the fake key and fake response
    out.payload.reserve(DecoyJSONResponse.size() + sizeof(FakeDecoyKey) + input.size());

    // 1. Copy decoy JSON
    out.payload.insert(out.payload.end(), DecoyJSONResponse.begin(), DecoyJSONResponse.end());

    // 2. Append subtly perturbed input data (silent data corruption)
    for (size_t i = 0; i < input.size(); ++i) {
        // Tweak sensitive mathematical coefficients so vendor business logic produces corrupted output
        uint8_t corrupted = input[i] ^ FakeDecoyKey[i % sizeof(FakeDecoyKey)] ^ 0x07;
        out.payload.push_back(corrupted);
    }

    return out;
}

uint8_t ChaffStateMachine::GetSteganographicTelemetryBit(bool is_poisoned) const {
    return is_poisoned ? 1 : 0;
}

} // namespace event_horizon::vm
