#pragma once

#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace event_horizon::vm {

// Custom language-specific exception handler compliant with Windows x64 SEH ABI
extern "C" EXCEPTION_DISPOSITION __cdecl EventHorizonExceptionHandler(
    PEXCEPTION_RECORD exceptionRecord,
    PVOID establisherFrame,
    PCONTEXT contextRecord,
    PVOID dispatcherContext
);

// Decoy mirage function routed to when external debugger hooks or VEH traps intercept unwinding
void MirageFunction();

// Installs the runtime function unwind table registration dynamically if needed
bool RegisterPDataIsland(uintptr_t code_start, size_t code_size);

} // namespace event_horizon::vm
