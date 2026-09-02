#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <span>
#include <chrono>

namespace event_horizon::session {

struct SessionState {
    uint64_t seq_num = 0;
    std::vector<uint8_t> prev_ack_hash;
    std::vector<uint8_t> active_dn_matrix;
    std::chrono::steady_clock::time_point last_successful_heartbeat;
    bool is_active = false;
    bool honeypot_triggered = false;
};

class SessionManager {
public:
    static std::unique_ptr<SessionManager> Create();
    virtual ~SessionManager() = default;

    virtual bool Initialize(const std::string& server_url,
                            const std::string& license_key,
                            std::span<const uint8_t> spki_pin,
                            uint32_t offline_grace_seconds) = 0;

    virtual std::vector<uint8_t> GetEphemeralPoPPublicKey() = 0;
    virtual bool EstablishSession(std::span<const uint8_t> lease_token,
                                 int64_t lease_exp_unix,
                                 std::span<const uint8_t> initial_d0) = 0;

    virtual bool SendHeartbeat(std::span<const uint8_t> state_acc_hash, bool honeypot_active) = 0;
    virtual bool IsGracePeriodExpired() const = 0;
    virtual std::span<const uint8_t> GetCurrentDnMatrix() const = 0;
    virtual void TerminateAndZeroize() = 0;
};

} // namespace event_horizon::session
