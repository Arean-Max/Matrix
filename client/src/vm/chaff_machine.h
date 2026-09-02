#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <string>

namespace event_horizon::vm {

struct DecoyOutput {
    std::vector<uint8_t> payload;
    bool honeypot_flag = false;
    uint32_t status_code = 0; // STATUS_SUCCESS (0)
};

class ChaffStateMachine {
public:
    ChaffStateMachine();
    ~ChaffStateMachine() = default;

    // Checks whether the state accumulator indicates poisoned execution.
    bool IsPoisoned(uint64_t current_accumulator, uint64_t expected_accumulator) const;

    // Executes deceptive decoy computation, returning mathematically plausible
    // fake keys and JSON structures to feed the analyst in x64dbg/Ghidra.
    DecoyOutput ExecuteDecoyRoutine(std::span<const uint8_t> input);

    // Steganographically encodes the honeypot triggered telemetry flag into heartbeat state.
    uint8_t GetSteganographicTelemetryBit(bool is_poisoned) const;
};

} // namespace event_horizon::vm
