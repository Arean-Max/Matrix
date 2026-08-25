# Event Horizon (Spec v12) — Threat Model & Trust Boundaries

## Section 0: Threat Model & Trust Boundaries (Non-Goals)

Event Horizon implements a Kerckhoffs-compliant licensing and code protection system under realistic adversary models. We reject marketing claims of "unbreakable" client-side security and formalize the boundaries of trust.

### 0.1 The OEP-Dump / Analog Hole (Accepted Risk & Economic Futility)
In von Neumann architecture machines, code must ultimately exist in physical RAM to be executed by the CPU. A dedicated attacker with root/kernel privileges or hypervisor access on their own physical hardware can dump the process memory space.

Event Horizon renders memory dumps economically futile for producing detached cracks:
1. **No Original Machine Code in Memory**: Protected routines do not reside as native x86_64 instructions in memory. They exist solely as bytecode interpreted across dual-entangled virtual machines (Stack VM $\alpha$ and Rule 30 Cellular Automaton $\beta$).
2. **Key Dissolution via White-Box Networks**: Raw 256-bit symmetric keys ($K_\text{payload}$) do not exist in contiguous buffers. Cryptographic operations are encoded into non-linear substitution-permutation networks ($T_i(x) = G_i \circ E_{k_i} \circ F_{i-1}^{-1}(x)$).
3. **No Static Business Logic Constants**: Critical state tables, Latin square diagonals, and automaton transition rules are intentionally carved out of the client binary and streamed on each cycle via dynamic epoch matrices ($D_n$). A memory dump captured at epoch $n$ lacks the operators required to execute epoch $n+1$.

### 0.2 Hardware-Bound Identity vs. Operating System Integrity
The baseline deployment guarantees that execution is bounded to a specific, unique TPM 2.0 silicon instance (**Identity-Bound**). It does not guarantee that the client host's OS kernel is unmodified. Protection against host tampering relies on TPM-backed sealing, attestation, and continuous server-client state entanglement.

### 0.3 EDR and Antivirus Coexistence
Malicious software packers and legacy protectors rely on direct syscalls, manual `ntdll` SSN resolution, thread hiding (`ThreadHideFromDebugger`), PEB/TEB inspection, and Vectored Exception Handler (VEH) page-fault hooks to intercept memory pages on demand. These techniques trigger alerts in modern Endpoint Detection and Response (EDR) platforms (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne).

Event Horizon uses only documented WinAPI, Windows CNG, Windows TBS (`tbs.dll`), and standard x64 structured exception handling (`.pdata` / `UNWIND_INFO`). Code modules are loaded into legitimate `MEM_IMAGE` sections via standard `LoadLibraryW`, followed by immediate POSIX file record deletion (`SetFileInformationByHandle` with `FileDispositionInfoEx` and `FILE_DISPOSITION_POSIX_SEMANTICS`).

### 0.4 Trust Levels
1. **`STANDARD_COMMERCIAL` (Default)**:
   - Pins raw EK public key upon initial Out-Of-Band (OOB) activation.
   - Software TPM emulators (`swtpm`) can pass this check if their NVRAM is copied.
   - Clones are detected deterministically via monotonic sequence numbers (`seq_num`), previous acknowledgment hashes (`prev_heartbeat_ack_hash`), and `SUPERSEDED` PoP key tracking on `/heartbeat`.
   - UI and database explicitly tag the node with `trust_level: unverified-hardware`.
2. **`STRICT_ENTERPRISE`**:
   - Enforces x509 certificate chain validation against trusted hardware vendor Certificate Authorities (Intel, AMD, Infineon, Nuvoton, STMicroelectronics).
   - Rejects uncertified hardware and emulators at the cryptographic boundary.
3. **`PERMISSIVE_DEV`**:
   - Allows execution on software emulators (`swtpm` / QEMU) for CI/CD testing.
   - Compiled strictly under `#ifdef DEV_BUILD` and physically excluded from production release binaries.

---

## Section 0.1: Known Problematic Anti-Patterns (Checklist)

| # | Anti-Pattern (DO NOT IMPLEMENT) | Required Implementation in Spec v12 |
| :- | :--- | :--- |
| **1** | Primitive debugger/VM API checks (`IsDebuggerPresent`, PEB, CPUID) that trip EDR and break Hyper-V/WSL2. | Heterogeneous LLVM pipeline + L1d cache-residency microarchitectural physics + server heartbeat. |
| **2** | TOFU (Trust-On-First-Use) without identity proof during initial binding. | OOB activation code delivered over vendor-pinned channel (email/webhook) established at sale. |
| **3** | HWID reset based only on cooldown quotas without OOB re-verification. | Every reset strictly requires new OOB `Activation_Code` challenge. |
| **4** | Reset quota checks implemented as raw read-then-write (TOCTOU race). | Atomic database transaction with pessimistic row-level locking (`SELECT ... FOR UPDATE`). |
| **5** | Development mode toggled via runtime configuration / `.env`. | Compile-time preprocessor directive `#ifdef DEV_BUILD`, completely omitted from release builds. |
| **6** | Lease token expiration validated against client system clock. | Cryptographically signed server timestamp embedded within token payload. |
| **7** | Heartbeat implemented as a bearer token valid across any channel. | Proof-of-Possession (PoP) signature from ephemeral client-generated key pair. |
| **8** | TPM Quote accepted without verifying AK migration attributes. | `TPM2_CertifyCreation` validation verifying `fixedTPM=1`, `fixedParent=1`, and `sensitiveDataOrigin=1`. |
| **9** | $K_\text{payload}$ transmitted in cleartext over TLS without TPM sealing. | Duplicable sealed object (`TPM2_Import`) bound to certified client SRK under target `PolicyPCR`. |
| **10** | Distinguishable timing/error responses on `/activate` for invalid keys. | Constant-time execution with identical error payload format for valid and invalid keys. |
| **11** | Static administrator tokens for approving/banning licenses. | mTLS with strict CRL validation or short-lived WebAuthn sessions with per-action audit logging. |
| **12** | Database encryption key stored in adjacent `.env` file or directory. | Key loaded from OS keyring (DPAPI / secret service) or interactive memory-only passphrase. |
| **13** | Arbitrary user text forwarded in telemetry to diagnostic LLMs. | Strictly typed numeric and enumeration schema; strings rejected at ingress to prevent prompt injection. |
| **14** | Missing protocol version enforcement allowing downgrade attacks. | `MIN_SUPPORTED_PROTOCOL_VERSION` gate rejecting legacy packets before payload parsing. |
| **15** | Builder storing or transmitting target server credentials for auto-deploy. | Builder outputs self-contained signed bundles; deployment executed via owner-managed channels. |
| **16** | Unsubstantiated marketing claims ("100% unbreakable", "uncrackable"). | Formulations framed strictly around asymmetric cost modeling, work factors, and license gating. |
| **17** | Server invoking `TPM2_Create` / `TPM2_Load` to seal for a foreign client chip. | Server produces `TPM2_Import`-compatible duplicable objects wrapped with client's public SRK. |
| **18** | Ephemeral PoP private key generated by server and transmitted to client. | PoP key pair generated strictly in client volatile RAM; only public key transmitted. |
| **19** | On-demand page decryption via VEH page-fault handler (`EXCEPTION_ACCESS_VIOLATION`). | Single-pass initialization via `TPM2_Unseal` + continuous dynamic matrix rotation ($D_n$). |
| **20** | Conflicting offline grace period defaults across modules. | Unified baseline default of 45 minutes (3 consecutive 15-minute cycles), configurable by admin. |
| **21** | Reflective PE mapping into `MEM_PRIVATE` memory as the default mode. | Path A (SDK/DLL) and Path A+ (Binary Lifting) as defaults; Path B (Reflective PE) as marked fallback. |
| **22** | Binding AK to EK using only `TPM2_CertifyCreation` without challenge. | Mandatory challenge-response via `TPM2_MakeCredential` and `TPM2_ActivateCredential`. |
| **23** | Clone detection relying on IP addresses or instant bans on restart. | Monotonic `seq_num` + `prev_heartbeat_ack_hash`; `SUPERSEDED` PoP key triggers ban only if reused concurrently. |
| **24** | Deleting active DLLs using standard `DeleteFileW` (fails with `ERROR_ACCESS_DENIED`). | POSIX unlink via `SetFileInformationByHandle` with `FILE_DISPOSITION_POSIX_SEMANTICS`. |
| **25** | Monolithic obfuscation using a single scheme easily removed by a single pass. | Heterogeneous combination of 8 orthogonal mathematical and physical layers. |
| **26** | Terminating process or showing error popups on debugger detection. | Implicit state poisoning into a Chaff State Machine and silent honeypot reporting. |

---

## Mathematical & Physical Foundations

### 1. Non-Associative Quasigroup MBA vs. SMT Bit-Vector Solvers
Standard Mixed Boolean-Arithmetic (MBA) operates in the commutative and associative ring $\mathbb{Z}_{2^{64}}$. State-of-the-art algebraic deobfuscators (e.g., SiMBA, GAMBA, Z3 bit-vector tactics) exploit ring identities:
$$(a \circ b) \circ c = a \circ (b \circ c)$$
$$a \circ b = b \circ a$$

Event Horizon projects arithmetic and boolean operators into finite non-associative, non-commutative quasigroups $(\mathbb{Q}, \ast)$ of order 256. A quasigroup is defined by a Latin square where every element appears exactly once in each row and column. We construct isotopic operations using non-linear bijective S-boxes:
$$x \ast y = P\bigl(S_1(x) \boxplus S_2(y)\bigr)$$
where $\boxplus$ is addition modulo 256, $S_1, S_2$ are distinct affine bijections, and $P$ is a bit-permutation.

Because $(x \ast y) \ast z \neq x \ast (y \ast z)$ and $x \ast y \neq y \ast x$, the associative and distributive laws do not hold. Graph-rewriting engines (such as LLVM `InstCombine`) and SMT simplifiers cannot fold expression trees without exhaustive state-space enumeration ($O(256^N)$ for a tree of depth $N$).

### 2. Microarchitectural CPU Physics vs. Debugger Hiding Plugins
Plugins such as ScyllaHide and TitanHide intercept user-mode debugging APIs and kernel hooks. However, they cannot modify the microarchitectural capacity of hardware CPU caches.

- An Intel/AMD x86_64 CPU core contains 32 KB or 48 KB of Level 1 Data (L1d) cache with 64-byte cache lines.
- Native continuous memory access to an L1d resident line executes in 4–5 clock cycles.
- When an interactive debugger breaks, single-steps, or switches tasks to an analysis tool, millions of instructions are executed by the OS kernel, DWM, and debugger UI, completely evicting the process cache lines into L3 or DRAM (>150 cycles).
- Hypervisor-based debuggers (hypervisor breakpoints, EPT hooks) incur VM-Exit and VM-Entry latency overhead ($>1{,}000$ cycles) and destroy TLB tagging.

Event Horizon samples an 8-cache-line probe set using serializing instruction barriers (`lfence; rdtsc`). If the measured latency exceeds 64 cycles, a binary flag is computed:
$$\text{EvictionBit} = (\Delta t > 64)$$
Rather than executing an explicit branch (`if (debugged) exit()`), the bit is fed directly into the state accumulator via quasigroup multiplication:
$$\text{State}_{next} = \text{QuasigroupMultiply}(\text{State}_{curr}, \text{Key} \oplus \text{EvictionBit})$$
A debugger single-step silently skews internal program state without providing the analyst with a breakpoint reference point.
