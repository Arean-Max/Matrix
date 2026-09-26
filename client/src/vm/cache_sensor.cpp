#include "cache_sensor.h"

#include <intrin.h>
#include <cstring>
#include <algorithm>

namespace event_horizon::vm {

namespace {

constexpr uint64_t L1D_CYCLE_THRESHOLD = 64; // Cycles > 64 indicate L3 / DRAM / VM-Exit latency

} // namespace

CacheResidencySensor::CacheResidencySensor() {
    // Populate probe buffer with non-zero initial entropy
    for (size_t i = 0; i < sizeof(probeBuffer_); ++i) {
        probeBuffer_[i] = static_cast<uint8_t>((i * 37) ^ 0xAA);
    }
}

uint8_t CacheResidencySensor::ProbeEvictionBit() {
    int evictionVotes = 0;

    // 2-of-3 majority filter to absorb scheduler context switches
    for (int trial = 0; trial < 3; ++trial) {
        // 1. Prime the 8 cache lines into L1d
        for (int line = 0; line < 8; ++line) {
            volatile uint8_t* p = &probeBuffer_[line * 64];
            *p = *p ^ static_cast<uint8_t>(line);
        }

        // 2. Serializing memory barrier before timing
        _mm_lfence();
        uint64_t startCycles = __rdtsc();
        _mm_lfence();

        // 3. Probe first and fourth cache lines
        volatile uint8_t val1 = probeBuffer_[0];
        volatile uint8_t val2 = probeBuffer_[3 * 64];
        (void)val1; (void)val2;

        _mm_lfence();
        uint64_t endCycles = __rdtsc();
        _mm_lfence();

        uint64_t delta = (endCycles > startCycles) ? (endCycles - startCycles) : L1D_CYCLE_THRESHOLD + 1;
        if (delta > L1D_CYCLE_THRESHOLD) {
            evictionVotes++;
        }
    }

    // Branchless majority vote (>= 2 votes returns 1)
    return (evictionVotes >= 2) ? 1 : 0;
}

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

uint64_t CacheResidencySensor::SampleCodeBytes(const void* function_ptr, size_t length) {
    if (!function_ptr || length == 0) {
        return 0;
    }

    // Verify memory page permissions to prevent memory access violations
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(function_ptr, &mbi, sizeof(mbi)) == 0) {
        return 0;
    }

    if (mbi.State != MEM_COMMIT) {
        return 0;
    }

    DWORD protect = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE);
    if (protect != PAGE_EXECUTE_READ && protect != PAGE_EXECUTE_READWRITE &&
        protect != PAGE_READONLY && protect != PAGE_READWRITE) {
        return 0;
    }

    // Clamp length to remaining committed bytes in this page
    uintptr_t funcAddr = reinterpret_cast<uintptr_t>(function_ptr);
    uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    if (funcAddr + length > regionEnd) {
        length = regionEnd - funcAddr;
    }

    const auto* code = static_cast<const uint8_t*>(function_ptr);
    uint64_t hash = 0xCBF29CE484222325ULL; // FNV-1a 64-bit

    for (size_t i = 0; i < length; ++i) {
        uint8_t byte = code[i];
        hash ^= byte;
        hash *= 0x100000001B3ULL;
    }

    return hash;
}

uint64_t CacheResidencySensor::ImplicitStateTransform(uint64_t state, uint64_t key) {
    uint8_t evictionBit = ProbeEvictionBit();
    // Zero-branch calculation: evictionBit skews key via bit shift
    uint64_t poisonedKey = key ^ (static_cast<uint64_t>(evictionBit) * 0x9E3779B97F4A7C15ULL);
    return (state * 6364136223846793005ULL) + poisonedKey;
}

} // namespace event_horizon::vm
