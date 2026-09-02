#include "../include/event_horizon.h"
#include "tpm/tpm_subsystem.h"
#include "session/session_manager.h"
#include "vm/dual_vm.h"
#include "vm/cache_sensor.h"
#include "vm/chaff_machine.h"
#include "sdk/loader.h"

#include <iostream>

namespace event_horizon {

class EventHorizonClientImpl final : public EventHorizonClient {
public:
    EventHorizonClientImpl()
        : tpmSubsystem_(tpm::TpmSubsystem::Create()),
          sessionManager_(session::SessionManager::Create()),
          dualVM_(vm::DualEntangledVM::Create()),
          chaffMachine_(std::make_unique<vm::ChaffStateMachine>()),
          cacheSensor_(std::make_unique<vm::CacheResidencySensor>()),
          moduleLoader_(std::make_unique<sdk::ProtectedModuleLoader>()) {}

    ~EventHorizonClientImpl() override {
        TerminateSession();
    }

    ClientStatus Initialize(const ClientConfig& config) override {
        config_ = config;

        if (!tpmSubsystem_->Initialize()) {
            return ClientStatus::HardwareAttestationFailed;
        }

        if (!sessionManager_->Initialize(config.server_url, config.license_key,
                                        config.spki_pin_hash, config.offline_grace_seconds)) {
            return ClientStatus::NotInitialized;
        }

        status_ = ClientStatus::Success;
        return status_;
    }

    ClientStatus StartSession() override {
        if (status_ != ClientStatus::Success) {
            return status_;
        }

        // 1. Collect attestation package with server challenge nonce
        std::vector<uint8_t> dummyNonce(32, 0x42);
        tpm::AttestationPackage pkg{};
        if (!tpmSubsystem_->GenerateAttestationPackage(dummyNonce, pkg)) {
            return ClientStatus::HardwareAttestationFailed;
        }

        // 2. Establish session and inject initial D0 matrix
        std::vector<uint8_t> leaseToken(64, 0x99);
        std::vector<uint8_t> d0Matrix(256, 0x11);
        int64_t leaseExp = 1893456000; // Future timestamp

        if (!sessionManager_->EstablishSession(leaseToken, leaseExp, d0Matrix)) {
            return ClientStatus::SessionRevoked;
        }

        dualVM_->IngestDynamicDn(d0Matrix);
        return ClientStatus::Success;
    }

    ClientStatus SubmitOOBCode(const std::string& code) override {
        if (code.length() != 6) {
            return ClientStatus::OOBVerificationRequired;
        }
        // Simulated client-side submission logic
        return ClientStatus::Success;
    }

    ClientStatus ExecuteProtectedRoutine(uint32_t routine_id,
                                         std::span<const uint8_t> input,
                                         std::vector<uint8_t>& output) override {
        if (sessionManager_->IsGracePeriodExpired()) {
            TerminateSession();
            return ClientStatus::OfflineGraceExpired;
        }

        // 1. Probe physical L1d cache residency and .text code bytes
        uint8_t evictionBit = cacheSensor_->ProbeEvictionBit();
        uint64_t codeHash = cacheSensor_->SampleCodeBytes(reinterpret_cast<const void*>(&MirageAnchor), 32);

        if (evictionBit != 0 || codeHash != 0) {
            // Implicit state poisoning - divert to Chaff State Machine
            isPoisoned_ = true;
            dualVM_->PoisonState(0xDEADBEEF);
        }

        if (isPoisoned_) {
            vm::DecoyOutput decoy = chaffMachine_->ExecuteDecoyRoutine(input);
            output = std::move(decoy.payload);
            // Steganographically mark honeypot flag for next heartbeat
            sessionManager_->SendHeartbeat(output, true);
            return ClientStatus::Success;
        }

        // 2. Standard execution in Dual-Entangled VM
        std::vector<uint8_t> bytecode = {
            static_cast<uint8_t>(vm::VMOpcode::PUSH_IMM),
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            static_cast<uint8_t>(vm::VMOpcode::PUSH_IMM),
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            static_cast<uint8_t>(vm::VMOpcode::ADD_Q),
            static_cast<uint8_t>(vm::VMOpcode::HALT)
        };

        uint64_t acc = 0;
        if (!dualVM_->Execute(bytecode, input, output, acc)) {
            return ClientStatus::NotInitialized;
        }

        // Send regular periodic heartbeat
        sessionManager_->SendHeartbeat(output, false);
        return ClientStatus::Success;
    }

    void TerminateSession() override {
        sessionManager_->TerminateAndZeroize();
        tpmSubsystem_->Shutdown();
        moduleLoader_->Unload();
        status_ = ClientStatus::NotInitialized;
    }

    bool IsHoneypotTriggered() const override {
        return isPoisoned_;
    }

private:
    static void MirageAnchor() {
        volatile int dummy = 42;
        (void)dummy;
    }

    ClientConfig config_;
    ClientStatus status_ = ClientStatus::NotInitialized;
    bool isPoisoned_ = false;

    std::unique_ptr<tpm::TpmSubsystem> tpmSubsystem_;
    std::unique_ptr<session::SessionManager> sessionManager_;
    std::unique_ptr<vm::DualEntangledVM> dualVM_;
    std::unique_ptr<vm::ChaffStateMachine> chaffMachine_;
    std::unique_ptr<vm::CacheResidencySensor> cacheSensor_;
    std::unique_ptr<sdk::ProtectedModuleLoader> moduleLoader_;
};

std::unique_ptr<EventHorizonClient> EventHorizonClient::Create() {
    return std::make_unique<EventHorizonClientImpl>();
}

} // namespace event_horizon
