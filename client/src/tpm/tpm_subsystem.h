#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <span>

namespace event_horizon::tpm {

struct AttestationPackage {
    std::vector<uint8_t> quote_attest;
    std::vector<uint8_t> quote_signature;
    std::vector<uint8_t> ak_creation_data;
    std::vector<uint8_t> ak_creation_ticket;
    std::vector<uint8_t> ak_certify_data;
    std::vector<uint8_t> ak_certify_sig;
    std::vector<uint8_t> srk_public;
    std::vector<uint8_t> srk_certify_data;
    std::vector<uint8_t> srk_certify_sig;
    std::vector<uint8_t> tcg_event_log;
};

class TpmSubsystem {
public:
    static std::unique_ptr<TpmSubsystem> Create();
    virtual ~TpmSubsystem() = default;

    virtual bool Initialize() = 0;
    virtual std::string GetEKPublicHash() = 0;
    virtual bool ActivateCredential(std::span<const uint8_t> credential_blob,
                                   std::span<const uint8_t> secret_blob,
                                   std::vector<uint8_t>& recovered_secret) = 0;
    virtual bool GenerateAttestationPackage(std::span<const uint8_t> server_nonce,
                                           AttestationPackage& out_package) = 0;
    virtual bool ImportAndUnsealPayload(std::span<const uint8_t> duplicate_private,
                                       std::span<const uint8_t> encrypted_secret,
                                       std::span<const uint8_t> target_policy_hash,
                                       std::vector<uint8_t>& out_payload_key) = 0;
    virtual void Shutdown() = 0;
};

} // namespace event_horizon::tpm
