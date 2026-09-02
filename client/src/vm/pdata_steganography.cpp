#include "pdata_steganography.h"

#include <iostream>
#include <atomic>

namespace event_horizon::vm {

namespace {

std::atomic<bool> g_mirageTriggered{false};

} // namespace

void MirageFunction() {
    g_mirageTriggered.store(true, std::memory_order_relaxed);
    // Silent decoy execution loop
    volatile int sink = 0x1337;
    for (int i = 0; i < 64; ++i) {
        sink = (sink * 31) ^ 0x5A;
    }
    (void)sink;
}

extern "C" EXCEPTION_DISPOSITION __cdecl EventHorizonExceptionHandler(
    PEXCEPTION_RECORD exceptionRecord,
    PVOID establisherFrame,
    PCONTEXT contextRecord,
    PVOID dispatcherContext
) {
    (void)establisherFrame;
    (void)dispatcherContext;

    if (!exceptionRecord || !contextRecord) {
        return ExceptionContinueSearch;
    }

    // Check for hardware breakpoints in debug registers (DR0-DR3)
    // and Trap Flag (TF, bit 8 in EFlags) indicating active single-stepping
    bool hardwareBreakpointActive = (contextRecord->Dr0 != 0 || contextRecord->Dr1 != 0 ||
                                     contextRecord->Dr2 != 0 || contextRecord->Dr3 != 0);
    bool trapFlagActive = (contextRecord->EFlags & 0x100) != 0;

    if (hardwareBreakpointActive || trapFlagActive) {
        // Redirect execution seamlessly to the mirage decoy routine
        contextRecord->Rip = reinterpret_cast<DWORD64>(&MirageFunction);
        // Clear trap flag to prevent continuous single-step exception looping
        contextRecord->EFlags &= ~0x100;
        return ExceptionContinueExecution;
    }

    // Normal control flow island transition:
    // If division by dynamic zero or deliberate access trap occurred,
    // advance instruction pointer past the trap instruction (typically 3 bytes for idiv or 4 bytes for mov)
    if (exceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO) {
        // Skip idiv opcode and resume at the target basic block island
        contextRecord->Rip += 3;
        // Inject non-associative state contribution into RAX
        contextRecord->Rax ^= 0x9E3779B97F4A7C15ULL;
        return ExceptionContinueExecution;
    }

    return ExceptionContinueSearch;
}

bool RegisterPDataIsland(uintptr_t code_start, size_t code_size) {
    if (code_start == 0 || code_size == 0) {
        return false;
    }

    // Allocate and register RUNTIME_FUNCTION for the memory region
    // via RtlAddFunctionTable
    RUNTIME_FUNCTION rf{};
    rf.BeginAddress = 0;
    rf.EndAddress = static_cast<DWORD>(code_size);
    rf.UnwindData = 0; // In production binary, points to UNWIND_INFO struct in .rdata

    // Dynamic registration for JIT or decrypted code regions
    return RtlAddFunctionTable(&rf, 1, code_start) != FALSE;
}

} // namespace event_horizon::vm
