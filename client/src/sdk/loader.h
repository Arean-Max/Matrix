#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <string>
#include <memory>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace event_horizon::sdk {

class ProtectedModuleLoader {
public:
    ProtectedModuleLoader();
    ~ProtectedModuleLoader();

    // Decrypts payload into a temporary file protected by restricted ACL,
    // loads it via LoadLibraryW into a clean MEM_IMAGE section,
    // and immediately unlinks the file from NTFS directory via POSIX semantics.
    bool LoadProtectedLibrary(std::span<const uint8_t> encrypted_payload,
                              std::span<const uint8_t> payload_key,
                              HMODULE& out_module);

    void Unload();

private:
    HMODULE loadedModule_ = nullptr;
    std::wstring tempFilePath_;
};

} // namespace event_horizon::sdk
