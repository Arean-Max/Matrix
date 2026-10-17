# EHVM1 — the payload bytecode machine

`eh-core` runs one vendor-supplied program per session. The program turns the
session's `vm_seed` into whatever per-session material the payload needs —
asset keys, integrity values, per-machine identifiers — without embedding
those values in the shipped binary.

Honesty first: **the VM is not a security boundary.** Bytecode travels inside
the `.ehpkg` payload and executes on the client, where a determined attacker
can always read memory and keys. The VM exists so vendors do not have to write
their own "obfuscated key derivation" — they get a small, testable, documented
machine instead. Trust still comes from the server session, never from the VM.

## Machine model

- **Words** are exactly 32 bytes. Everything on the stack, in memory and on
  the input ports is one word.
- **Arithmetic** (`ADD`) treats a word as an unsigned big-endian 256-bit
  integer: byte 0 is the most significant, byte 31 the least significant,
  overflow beyond byte 0 is dropped (mod 2^256). Hex constants written as
  `0x…` are right-aligned big-endian numbers, text constants are left-aligned
  (byte 0 is the first character).
- **Stack** is a plain word stack, operated on from the top. `j n` in the
  tables below means: pop `n` words, then push the result.
- **Memory** is 16 word slots (`0..=15`), zero-initialized per run.
- **Inputs** are up to 8 words (`0..=7`) supplied by the host; missing slots
  read as zero.
- **Seed** is the session `vm_seed`: `HMAC-SHA256(kVM, session_id)` computed
  by the server, delivered once at `/verify`. The VM never stores or derives
  it further.
- **Output** is a byte buffer: every `OUT` appends one 32-byte word. The host
  reads it when the program halts.
- Determinism: same seed + same inputs + same bytecode ⇒ same output. No
  randomness, no clock, no environment, no I/O beyond the output buffer.
- **Gas**: at most [`MAX_STEPS`] = 1,000,000 executed instructions per run.

## Bytecode layout

```
offset  size        meaning
0       5           magic "EHVM1"
5       2           u16 big-endian: constant count
7       32*count    constants, each exactly 32 bytes
…       4           u32 big-endian: code length in bytes
…       code_len    code bytes
```

Parsing is strict: wrong magic, a truncated section, or any trailing byte is
`VmError::Malformed`. There is no version negotiation inside the container —
the magic is the version.

## Instruction set

One-byte opcodes; operands are immediate, big-endian, and read in order.

| Op | Code | Operand | Stack effect | Semantics |
|----|------|---------|--------------|-----------|
| `HALT` | 0x00 | — | — | stop; the program must not fall off the end |
| `PUSH i` | 0x01 | u16 const index | push 1 | push `consts[i]` |
| `SEED` | 0x02 | — | push 1 | push the session seed |
| `LOAD s` | 0x03 | u8 slot | push 1 | push `mem[s]` |
| `STORE s` | 0x04 | u8 slot | pop 1 | `mem[s] = top` |
| `DUP` | 0x05 | — | push 1 | duplicate the top word |
| `DROP` | 0x06 | — | pop 1 | discard the top word |
| `SWAP` | 0x07 | — | swap | swap the top two words |
| `XOR` | 0x08 | — | pop 2, push 1 | `a ^ b`, byte-wise |
| `ADD` | 0x09 | — | pop 2, push 1 | `a + b mod 2^256`, big-endian |
| `SHA` | 0x0A | — | pop 1, push 1 | `SHA-256(a)` |
| `HMAC` | 0x0B | — | pop 2, push 1 | `HMAC-SHA256(key, msg)`; the message is on top, the key below it |
| `CMP` | 0x0C | — | pop 2, push 1 | `a == b` ? 32 × `0xFF` : 32 × `0x00` |
| `JNZ off` | 0x0D | i16 | pop 1 | if any byte of the word is nonzero, jump to `off` bytes **after the operand**; target is checked against `0..=code_len` |
| `OUT` | 0x0E | — | pop 1 | append the word to the output buffer |
| `INPUT s` | 0x0F | u8 slot | push 1 | push `inputs[s]` (zero-filled if absent) |

Every opcode may fail with `StackUnderflow`, `BadConstIndex`, `BadSlot`,
`BadOpcode`, `OutOfGas` (step limit), or `Malformed` (instruction operand
reads past the end, or execution runs past the end of the code). These are
bug indicators in the bytecode or the host, never environment errors.

## Assembler

`eh_core::asm` translates a line-oriented text form into the binary layout.
It is meant for building payloads, not for shipping to clients.

- `.const "text"` — ASCII/UTF-8 text, left-aligned into the word.
- `.const 0xHEX` — an even number of hex digits ≤ 64, right-aligned as a
  big-endian number. `0x01` is the value 1.
- One instruction per line; case-sensitive lowercase mnemonics; operands are
  decimal (`push 3`, `load 0`, `jnz label`) or hex via `0x…` where the ISA
  says u8/u16/i16.
- `name:` on its own line defines a label; `jnz name` computes the relative
  offset from the end of the instruction to that label.
- `;` starts a comment.
- Labels cannot be forward-referenced across more than one pass — the
  assembler resolves them after collecting all lines.

## Examples

These programs are covered by tests in `rust/eh-core`, so the documentation
cannot rot.

Derive a per-session key labelled `asset-key/v1`:

```
seed
.const "asset-key/v1"
push 0        ; the constant defined above
hmac          ; HMAC-SHA256(key = seed, msg = label)
out
halt
```

Compare and branch:

```
.const 0x01
push 0
push 0
cmp           ; all-ones since 0x01 == 0x01
jnz hit
.const "no"
push 1
out
halt
hit:
.const "yes"
push 2
out
halt
```

## Host integration

1. The payload arrives as an `.ehpkg` container and is opened by the client
   after `/verify` (see `docs/PROTOCOL.md` §5).
2. The host parses the payload with `eh_core::Bytecode::parse`, constructs a
   VM with the session seed (`Vm::with_seed` or `Vm::new` with inputs) and
   calls `run`.
3. The returned bytes are the program's output. The session's `vm_seed` is
   per-session material: the same program on the next session produces
   different output by design.

## Versioning

`EHVM1` is frozen. Any change to an opcode, an operand encoding, the binary
layout or the address arithmetic requires a new magic (`EHVM2`) and a new
document; silent extensions are forbidden.
