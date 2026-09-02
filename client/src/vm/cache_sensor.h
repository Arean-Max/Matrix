#pragma once

#include <cstdint>
#include <span>

namespace event_horizon::vm {

class CacheResidencySensor {
public:
    CacheResidencySensor();
    ~CacheResidencySensor() = default;

    // Evaluates L1d eviction latency using 2-of-3 majority filter.
    // Returns 0 if resident in L1d (native continuous execution),
    // returns 1 if evicted into L3/DRAM (debugger step-over / VM-exit).
    uint8_t ProbeEvictionBit();

    // Direct code-as-key hashing of .text memory region.
    // Returns checksum contribution. Software breakpoints (0xCC/INT3) alter this value.
    uint64_t SampleCodeBytes(const void* function_ptr, size_t length);

    // Integrates eviction bit and code byte hash into current state accumulator
    // via implicit non-associative poisoning (no branch checks).
    uint64_t ImplicitStateTransform(uint64_t state, uint64_t key);

private:
    alignas(64) uint8_t probeBuffer_[512]{}; // 8 cache lines (64 bytes each)
};

} // namespace event_horizon::vm
