#include "loader.h"

#include <bcrypt.h>
#include <sddl.h>
#include <vector>
#include <array>
#include <format>
#include <iostream>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace event_horizon::sdk {

namespace {

// Windows 10/11 FileDispositionInfoEx definitions
constexpr FILE_INFO_BY_HANDLE_CLASS EH_FileDispositionInfoEx = static_cast<FILE_INFO_BY_HANDLE_CLASS>(21);

struct EH_FILE_DISPOSITION_INFO_EX {
    DWORD Flags;
};

constexpr DWORD EH_FILE_DISPOSITION_FLAG_DELETE          = 0x00000001;
constexpr DWORD EH_FILE_DISPOSITION_FLAG_POSIX_SEMANTICS = 0x00000002;

bool UnlinkFilePOSIX(HANDLE hFile) {
    if (!hFile || hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    EH_FILE_DISPOSITION_INFO_EX dispInfo{};
    dispInfo.Flags = EH_FILE_DISPOSITION_FLAG_DELETE | EH_FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;

    return SetFileInformationByHandle(hFile, EH_FileDispositionInfoEx, &dispInfo, sizeof(dispInfo)) != FALSE;
}

} // namespace

ProtectedModuleLoader::ProtectedModuleLoader() = default;

ProtectedModuleLoader::~ProtectedModuleLoader() {
    Unload();
}

bool ProtectedModuleLoader::LoadProtectedLibrary(std::span<const uint8_t> encrypted_payload,
                                                 std::span<const uint8_t> payload_key,
                                                 HMODULE& out_module) {
    if (encrypted_payload.empty() || payload_key.empty()) {
        return false;
    }

    // 1. Simple stream decryption of payload into memory buffer
    // (In production, this runs through the White-Box table network)
    std::vector<uint8_t> decrypted(encrypted_payload.size());
    for (size_t i = 0; i < encrypted_payload.size(); ++i) {
        decrypted[i] = encrypted_payload[i] ^ payload_key[i % payload_key.size()] ^ 0x5C;
    }

    // Verify PE magic headers ('MZ') before touching disk
    if (decrypted.size() < 2 || decrypted[0] != 'M' || decrypted[1] != 'Z') {
        return false;
    }

    // 2. Generate path for temporary DLL
    wchar_t tempDir[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tempDir);
    wchar_t tempFile[MAX_PATH]{};
    GetTempFileNameW(tempDir, L"EH_", 0, tempFile);
    tempFilePath_ = tempFile;

    // 3. Create file with restricted DACL (D:(A;;GA;;;OW) -> Grant All to Owner only)
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;OW)", SDDL_REVISION_1, &pSD, nullptr)) {
        return false;
    }
    sa.lpSecurityDescriptor = pSD;

    HANDLE hFile = CreateFileW(tempFilePath_.c_str(),
                               GENERIC_READ | GENERIC_WRITE | DELETE,
                               FILE_SHARE_READ, // Allow LoadLibrary to read
                               &sa,
                               CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL,
                               nullptr);
    LocalFree(pSD);

    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD bytesWritten = 0;
    WriteFile(hFile, decrypted.data(), static_cast<DWORD>(decrypted.size()), &bytesWritten, nullptr);

    // 4. Load library as standard MEM_IMAGE (EDR-clean)
    loadedModule_ = LoadLibraryW(tempFilePath_.c_str());

    // 5. Immediate POSIX Unlink while image section remains mapped in memory
    UnlinkFilePOSIX(hFile);
    CloseHandle(hFile);

    // Fallback: regular DeleteFileW in case filesystem does not support POSIX semantics
    DeleteFileW(tempFilePath_.c_str());

    if (!loadedModule_) {
        return false;
    }

    out_module = loadedModule_;
    return true;
}

void ProtectedModuleLoader::Unload() {
    if (loadedModule_) {
        FreeLibrary(loadedModule_);
        loadedModule_ = nullptr;
    }
}

} // namespace event_horizon::sdk
