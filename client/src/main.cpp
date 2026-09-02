#include "../include/event_horizon.h"
#include <iostream>
#include <vector>

int main() {
    std::cout << "[Event Horizon] Initializing Client Runtime (Spec v12)..." << std::endl;

    auto client = event_horizon::EventHorizonClient::Create();
    event_horizon::ClientConfig config{};
    config.server_url = "https://127.0.0.1:8443";
    config.license_key = "EH-TEST-KEY-128BIT-ENTROPY";
    config.offline_grace_seconds = 2700; // 45 minutes default

    auto status = client->Initialize(config);
    if (status != event_horizon::ClientStatus::Success) {
        std::cerr << "[-] Initialization failed: " << static_cast<uint32_t>(status) << std::endl;
        return 1;
    }
    std::cout << "[+] TPM subsystem and Session Manager initialized." << std::endl;

    status = client->StartSession();
    if (status != event_horizon::ClientStatus::Success) {
        std::cerr << "[-] StartSession failed: " << static_cast<uint32_t>(status) << std::endl;
        return 1;
    }
    std::cout << "[+] Lease established and initial D0 matrix ingested." << std::endl;

    std::vector<uint8_t> input(16, 0x55);
    std::vector<uint8_t> output;
    status = client->ExecuteProtectedRoutine(1, input, output);
    if (status != event_horizon::ClientStatus::Success) {
        std::cerr << "[-] Execution failed: " << static_cast<uint32_t>(status) << std::endl;
        return 1;
    }

    std::cout << "[+] Protected routine executed successfully in Dual-VM. Output bytes: " << output.size() << std::endl;
    std::cout << "[+] Honeypot triggered: " << (client->IsHoneypotTriggered() ? "YES (Decoy Active)" : "NO (Clean)") << std::endl;

    client->TerminateSession();
    std::cout << "[+] Session terminated and volatile memory zeroized." << std::endl;
    return 0;
}
