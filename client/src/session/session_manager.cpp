#include "session_manager.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <vector>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <format>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")

namespace event_horizon::session {

namespace {

void SecureZero(void* ptr, size_t size) {
    if (ptr && size > 0) {
        SecureZeroMemory(ptr, size);
    }
}

std::vector<uint8_t> ComputeSHA256(std::span<const uint8_t> data) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    std::vector<uint8_t> hash(32);
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        BCryptHash(hAlg, nullptr, 0, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), hash.data(), static_cast<ULONG>(hash.size()));
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    return hash;
}

} // namespace

class SessionManagerImpl final : public SessionManager {
public:
    SessionManagerImpl() = default;
    ~SessionManagerImpl() override {
        TerminateAndZeroize();
    }

    bool Initialize(const std::string& server_url,
                    const std::string& license_key,
                    std::span<const uint8_t> spki_pin,
                    uint32_t offline_grace_seconds) override {
        serverUrl_ = server_url;
        licenseKey_ = license_key;
        spkiPin_.assign(spki_pin.begin(), spki_pin.end());
        offlineGraceSeconds_ = offline_grace_seconds;

        // Generate ephemeral PoP key pair strictly in RAM
        if (!GenerateEphemeralPoPKey()) {
            return false;
        }

        state_.seq_num = 0;
        state_.prev_ack_hash.assign(32, 0);
        state_.is_active = false;
        return true;
    }

    std::vector<uint8_t> GetEphemeralPoPPublicKey() override {
        return popPublicKey_;
    }

    bool EstablishSession(std::span<const uint8_t> lease_token,
                          int64_t lease_exp_unix,
                          std::span<const uint8_t> initial_d0) override {
        leaseToken_.assign(lease_token.begin(), lease_token.end());
        leaseExpUnix_ = lease_exp_unix;
        state_.active_dn_matrix.assign(initial_d0.begin(), initial_d0.end());
        state_.seq_num = 1;
        state_.prev_ack_hash = ComputeSHA256(initial_d0);
        state_.last_successful_heartbeat = std::chrono::steady_clock::now();
        state_.is_active = true;
        return true;
    }

    bool SendHeartbeat(std::span<const uint8_t> state_acc_hash, bool honeypot_active) override {
        if (!state_.is_active) {
            return false;
        }

        if (IsGracePeriodExpired()) {
            TerminateAndZeroize();
            return false;
        }

        // Construct canonical payload for PoP signature:
        // LicenseKey || SeqNum (Big Endian) || PrevAckHash || StateAccHash || HoneypotTriggered
        std::vector<uint8_t> digestInput;
        digestInput.insert(digestInput.end(), licenseKey_.begin(), licenseKey_.end());

        uint64_t seqBe = _byteswap_uint64(state_.seq_num);
        const uint8_t* seqBytes = reinterpret_cast<const uint8_t*>(&seqBe);
        digestInput.insert(digestInput.end(), seqBytes, seqBytes + 8);
        digestInput.insert(digestInput.end(), state_.prev_ack_hash.begin(), state_.prev_ack_hash.end());
        digestInput.insert(digestInput.end(), state_acc_hash.begin(), state_acc_hash.end());
        digestInput.push_back(honeypot_active ? 1 : 0);

        std::vector<uint8_t> payloadDigest = ComputeSHA256(digestInput);
        std::vector<uint8_t> signature = SignPayload(payloadDigest);

        // Advance local monotonic sequence
        state_.seq_num++;

        // Simulate local network round-trip / response verification
        // In full deployment, this transmits over WinHTTP with SPKI pinning
        std::vector<uint8_t> newAckHash(32);
        for (size_t i = 0; i < 32; ++i) {
            newAckHash[i] = payloadDigest[i] ^ state_.prev_ack_hash[i] ^ 0x3C;
        }
        state_.prev_ack_hash = newAckHash;
        state_.last_successful_heartbeat = std::chrono::steady_clock::now();

        // Mutate dynamic Dn matrix for next epoch (Continuous Data Entanglement)
        for (size_t i = 0; i < state_.active_dn_matrix.size(); ++i) {
            state_.active_dn_matrix[i] ^= newAckHash[i % newAckHash.size()];
        }

        return true;
    }

    bool IsGracePeriodExpired() const override {
        if (!state_.is_active) {
            return true;
        }
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - state_.last_successful_heartbeat).count();
        return elapsed > static_cast<int64_t>(offlineGraceSeconds_);
    }

    std::span<const uint8_t> GetCurrentDnMatrix() const override {
        return state_.active_dn_matrix;
    }

    void TerminateAndZeroize() override {
        state_.is_active = false;
        SecureZero(state_.active_dn_matrix.data(), state_.active_dn_matrix.size());
        state_.active_dn_matrix.clear();

        SecureZero(popPrivateKey_.data(), popPrivateKey_.size());
        popPrivateKey_.clear();

        SecureZero(popPublicKey_.data(), popPublicKey_.size());
        popPublicKey_.clear();

        SecureZero(leaseToken_.data(), leaseToken_.size());
        leaseToken_.clear();

        if (hKey_) {
            BCryptDestroyKey(hKey_);
            hKey_ = nullptr;
        }
        if (hSignAlg_) {
            BCryptCloseAlgorithmProvider(hSignAlg_, 0);
            hSignAlg_ = nullptr;
        }
    }

private:
    bool GenerateEphemeralPoPKey() {
        if (BCryptOpenAlgorithmProvider(&hSignAlg_, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) != 0) {
            return false;
        }
        if (BCryptGenerateKeyPair(hSignAlg_, &hKey_, 256, 0) != 0) {
            return false;
        }
        if (BCryptFinalizeKeyPair(hKey_, 0) != 0) {
            return false;
        }

        // Export public key blob
        ULONG pubBlobSize = 0;
        if (BCryptExportKey(hKey_, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &pubBlobSize, 0) != 0) {
            return false;
        }
        popPublicKey_.resize(pubBlobSize);
        if (BCryptExportKey(hKey_, nullptr, BCRYPT_ECCPUBLIC_BLOB, popPublicKey_.data(), pubBlobSize, &pubBlobSize, 0) != 0) {
            return false;
        }

        // Seed 32-byte ephemeral identifier
        popPrivateKey_.resize(32);
        BCryptGenRandom(nullptr, popPrivateKey_.data(), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        return true;
    }

    std::vector<uint8_t> SignPayload(std::span<const uint8_t> digest) {
        if (!hKey_) {
            return {};
        }
        ULONG sigSize = 0;
        if (BCryptSignHash(hKey_, nullptr, const_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()),
                           nullptr, 0, &sigSize, 0) != 0) {
            return {};
        }
        std::vector<uint8_t> sig(sigSize);
        if (BCryptSignHash(hKey_, nullptr, const_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()),
                           sig.data(), sigSize, &sigSize, 0) != 0) {
            return {};
        }
        return sig;
    }

    std::string serverUrl_;
    std::string licenseKey_;
    std::vector<uint8_t> spkiPin_;
    uint32_t offlineGraceSeconds_ = 2700;

    BCRYPT_ALG_HANDLE hSignAlg_ = nullptr;
    BCRYPT_KEY_HANDLE hKey_ = nullptr;
    std::vector<uint8_t> popPublicKey_;
    std::vector<uint8_t> popPrivateKey_;
    std::vector<uint8_t> leaseToken_;
    int64_t leaseExpUnix_ = 0;

    SessionState state_;
};

std::unique_ptr<SessionManager> SessionManager::Create() {
    return std::make_unique<SessionManagerImpl>();
}

} // namespace event_horizon::session
