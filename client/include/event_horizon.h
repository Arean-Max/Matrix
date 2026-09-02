#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <memory>

namespace event_horizon {

enum class ClientStatus : uint32_t {
    Success = 0,
    NotInitialized,
    HardwareAttestationFailed,
    OOBVerificationRequired,
    SessionRevoked,
    SupersededSession,
    CloneDetected,
    OfflineGraceExpired,
    NetworkError
};

struct ClientConfig {
    std::string server_url;
    std::string license_key;
    std::vector<uint8_t> spki_pin_hash; // SHA-256 of server public key
    uint32_t offline_grace_seconds = 2700; // 45 minutes baseline default
    bool strict_enterprise = false;
};

class EventHorizonClient {
public:
    static std::unique_ptr<EventHorizonClient> Create();
    virtual ~EventHorizonClient() = default;

    virtual ClientStatus Initialize(const ClientConfig& config) = 0;
    virtual ClientStatus StartSession() = 0;
    virtual ClientStatus SubmitOOBCode(const std::string& code) = 0;
    virtual ClientStatus ExecuteProtectedRoutine(uint32_t routine_id,
                                                std::span<const uint8_t> input,
                                                std::vector<uint8_t>& output) = 0;
    virtual void TerminateSession() = 0;
    virtual bool IsHoneypotTriggered() const = 0;
};

} // namespace event_horizon
