# Turnkey Protection Guide (No-Code Integration)

Event Horizon provides a zero-code runtime guard (`eh-guard`) that wraps any pre-compiled Windows executable (`.exe`) inside ChaCha20-Poly1305 authenticated envelope encryption.

The executable payload stays encrypted on disk as an `.ehpkg` container. The decryption key is held strictly by the licensing server (`eh-server`) and is never written to disk or exposed over the wire in plaintext. At launch, `eh-guard` validates hardware attestation with the server, acquires an ephemeral session key, decrypts the payload into a guarded memory/staging buffer, spawns the process, and continuously validates heartbeat leases. If a license is revoked, suspended, or tampered with, execution is halted immediately.

---

## Architecture Overview

```
 [ Developer / Laptop (Server) ]                       [ User / PC (Client) ]
  ┌─────────────────────────┐                           ┌────────────────────────┐
  │  hello.exe (Unprotected)│                           │  guard.json            │
  └────────────┬────────────┘                           │  hello-app.ehpkg       │
               │                                        │  certs/ca.pem          │
       (eh-builder pack)                                └───────────┬────────────┘
               │                                                    │
       ┌───────┴───────────────┐                                    │
       │                       │                            (eh-guard launch)
       ▼                       ▼                                    │
 hello-app.ehpkg        hello-app.provision.json                    │
 (Safe to distribute)   (Secret Server Key)                         ▼
       │                       │                         ┌───────────────────────┐
       │             (ehctl packages import)             │ Hardware Attestation  │
       │                       │                         │ (TPM 2.0 / DPAPI)     │
       │                       ▼                         └──────────┬────────────┘
       │              ┌──────────────────┐                          │
       │              │  eh-server:8443  │◄─────────────────────────┘
       │              │  (Laptop Server) │  mTLS / P-256 Key Exchange
       │              └────────┬─────────┘  Token Chaining & Heartbeats
       │                       │
       └───────────────────────┼────────────────────────────────────┐
                               ▼                                    ▼
                     [ Issue License Key ]                [ Decrypt & Execute ]
```

---

## 1. Server Setup (Laptop)

### Step 1.1: Generate TLS Certificates
In production, use public certificates or an internal PKI. For local testing across your LAN, generate an ECDSA P-256 certificate:

```powershell
# Create certs directory
New-Item -ItemType Directory -Force certs

# Generate ECDSA CA and Server Certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes `
  -keyout certs/ca.key -out certs/ca.pem -days 365 -subj "/CN=EventHorizonCA"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes `
  -keyout certs/key.pem -out certs/server.csr -subj "/CN=EventHorizonServer"

openssl x509 -req -in certs/server.csr -CA certs/ca.pem -CAkey certs/ca.key `
  -CAcreateserial -out certs/cert.pem -days 365 `
  -extfile <(printf "subjectAltName=IP:127.0.0.1,IP:YOUR_LAPTOP_IP,DNS:localhost")
```

### Step 1.2: Configure `server.yaml`
Create `server.yaml`:

```yaml
listen: "0.0.0.0:8443"
data_dir: "data"

tls:
  cert_file: "certs/cert.pem"
  key_file: "certs/key.pem"

lease_ttl_hours: 48
offline_grace_hours: 72
heartbeat_interval_sec: 60

oob:
  code_ttl_min: 30
  max_attempts: 5
  resend_interval_sec: 60

attestation:
  mode: "auto" # automatically enables TPM 2.0 attestation when supported

security:
  supersede_grace_s: 300
  min_response_floor_ms: 10
```

### Step 1.3: Start `eh-server`
```powershell
.\eh-server.exe --config server.yaml
```
On first launch, the server generates `data/bootstrap.token`.

### Step 1.4: Initialize Operator CLI (`ehctl`)
In another shell on the laptop:
```powershell
.\ehctl.exe init --server https://127.0.0.1:8443 --ca certs/ca.pem --bootstrap-file data/bootstrap.token --name "admin-cli"
```

---

## 2. Protecting Any Program (No Code Required)

### Step 2.1: Pack the Executable
Take your target binary (e.g., `hello.exe`):

```powershell
.\eh-builder.exe pack --id hello-app --name "Hello World Protected" --in hello.exe --out dist_client
```

Output:
- `dist_client/hello-app.ehpkg`: The encrypted container (safe to distribute to users).
- `dist_client/hello-app.provision.json`: The secret provisioning metadata containing the symmetric container key.

### Step 2.2: Register the Package with the Server
Import the provisioning metadata into `eh-server`:
```powershell
.\ehctl.exe packages import dist_client/hello-app.provision.json --server https://127.0.0.1:8443 --ca certs/ca.pem
```
> [!IMPORTANT]
> Delete or store `hello-app.provision.json` offline. Never distribute it to clients.

### Step 2.3: Issue a Customer License
```powershell
.\ehctl.exe license create --customer "Client PC 1" --max-devices 1 --server https://127.0.0.1:8443 --ca certs/ca.pem
```
This prints the single-use raw license key:
```text
license id:  3d7467a0b614f4c7204bd57e85689525
license key: EH1-9KEVJ-WNPQY-84RQZ-SD3CA
```

---

## 3. Client Setup (Desktop / User PC)

Distribute the following files to the client machine:
1. `eh-guard.exe`
2. `hello-app.ehpkg`
3. `certs/ca.pem`
4. `guard.json` (configuration file)

### Step 3.1: Create `guard.json`
```json
{
  "server": "https://<LAPTOP_IP>:8443",
  "ca_file": "certs/ca.pem",
  "license": "EH1-9KEVJ-WNPQY-84RQZ-SD3CA",
  "package_id": "hello-app",
  "package_file": "hello-app.ehpkg",
  "kill_on_lease_expiry": true
}
```

### Step 3.2: First-Time Activation
Run `eh-guard.exe`:
```powershell
.\eh-guard.exe --config guard.json
```

If Out-Of-Band (OOB) hardware activation is required:
```text
eh-guard: activation needs an out-of-band code (expires at 1792882115)
eh-guard: an administrator can reveal it with: ehctl license oob <license-id>
```

On the Laptop (Server), reveal the 8-digit activation code:
```powershell
.\ehctl.exe license oob 3d7467a0b614f4c7204bd57e85689525 --server https://127.0.0.1:8443 --ca certs/ca.pem
```
Output:
```text
code:        59870005
fingerprint: f52bbd3da8d704d4da518fdfd3d1b99eb63a7e72da7da47e5981a54c4e9a5d81
expires:     2026-10-24 18:48:35
```

On the Client PC, submit the activation code:
```powershell
.\eh-guard.exe --config guard.json --code 59870005
```

The application unpacks, starts instantly, and executes securely!

### Step 3.3: Subsequent Launches
For subsequent launches on that computer:
```powershell
.\eh-guard.exe --config guard.json
```
`eh-guard` validates the persisted session state, verifies heartbeats in the background, and allows offline execution up to `offline_grace_hours`.

---

## 4. Live Administration & Revocation

### Suspending a License
To block access immediately:
```powershell
.\ehctl.exe license suspend 3d7467a0b614f4c7204bd57e85689525 --reason "Payment overdue"
```
When the client attempts to run:
```text
eh-guard: client: server 403 license_unavailable: license is not active
```

### Resuming a License
```powershell
.\ehctl.exe license resume 3d7467a0b614f4c7204bd57e85689525
```

### Permanent Revocation
```powershell
.\ehctl.exe license revoke 3d7467a0b614f4c7204bd57e85689525 --reason "Terms of Service violation"
```
Once revoked, the license can never be reused or activated.
