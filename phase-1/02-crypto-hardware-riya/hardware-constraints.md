# Hardware Constraints and Migration Feasibility

## Purpose

Identify what a future hardware signing backend must provide. This phase does not implement USB transport, firmware, or hardware ML-DSA.

## Common requirements

Every hardware target must be evaluated for:

- peak RAM during key generation and signing;
- flash/program size;
- persistent protected-key storage;
- cryptographically secure random-number generation;
- CPU architecture and instruction support;
- signing latency and power consumption;
- constant-time and side-channel-resistant implementation availability;
- USB HID or serial support;
- request framing, maximum message size, and transport latency;
- firmware authenticity and update/recovery mechanism;
- PIN retry enforcement and device reset behavior;
- physical extraction and fault-injection exposure.

Private-key size alone is not proof of feasibility. Peak working memory, stack, temporary polynomial buffers, hashing state, randomness, and implementation strategy must also be measured.

## Target A: Desktop or Linux single-board computer

Examples: x86-64 desktop, Raspberry Pi running Linux.

| Question | Finding | Evidence |
|---|---|---|
| Does liboqs build natively? | Yes on Windows 11 x64 (MSVC, Debug). Raspberry Pi/Linux untested. | `liboqs-validation.md` |
| Are all ML-DSA variants enabled? | Yes: ML-DSA-44/65/87 | Runtime enumeration |
| Peak signing memory | Not measured | Open: measure on Linux with an optimized build |
| Signing latency | 1.7–3.5 ms median on desktop | `experiments/results.md` |
| Shared-library/deployment requirements | `oqs` shared library built on first import; the Python wrapper must find it | `phase2/DEVELOPMENT.md` |
| Suitable for first hardware-like prototype? | Yes as a *protocol* stand-in: the prototype's virtual token runs the same signing core in a separate process. It is not a security boundary. | `quantumkey/authenticator/token.py` |

## Target B: Raspberry Pi Pico / RP2040

The RP2040 is substantially more constrained than a Linux Raspberry Pi. Treat them as different target classes.

| Question | Finding | Evidence |
|---|---|---|
| Available SRAM and flash | 264 KB on-chip SRAM. Flash is **external** QSPI (up to 16 MB), so key material in flash sits on a separate, probeable chip. | RP2040 datasheet |
| Compatible portable ML-DSA implementation | Uncertain. The RP2040 is a dual Cortex-M0+; pqm4's optimized code targets Cortex-M4 and does not apply. Portable C (for example PQClean-derived ML-DSA) would be needed and must be ported and verified. | Architecture mismatch; to be verified |
| Peak signing RAM/stack | Unmeasured on RP2040. Indicative only: compact pre-standard Dilithium3 on Cortex-M4 needed about 9–11 KB stack for keygen/verify and 10.5–54 KB for signing depending on strategy. That fits 264 KB, but these are pre-standard Dilithium figures on a different core. | Greconici, Kannwischer, Sprenkels, *Compact Dilithium Implementations on Cortex-M3 and Cortex-M4*, IACR ePrint 2020/1278 |
| Estimated signing latency | Unmeasured. The same source reports about 10.7 M cycles for Dilithium3 signing on Cortex-M4 (about 85 ms at 125 MHz if it transferred, which is unlikely to be exact on M0+ without DSP instructions). Expect slower; measure. | ePrint 2020/1278; needs measurement |
| Secure randomness source | Unverified. The datasheet documents a ring-oscillator random bit; it is not documented as a cryptographic RNG and would need conditioning and review. | RP2040 datasheet; open |
| Protected nonvolatile key storage | None identified on RP2040 (no secure element, external flash). Keys would be readable by anyone with physical access unless an external secure element or another chip is added. | Datasheet; open |
| USB Serial/HID feasibility | Native USB 1.1 device controller; CDC serial carries the token's length-framed protocol directly. | Datasheet; `quantumkey/authenticator/token.py` |
| Overall classification | **Uncertain**: likely feasible for a *functional* token demonstrating the protocol and policy enforcement, not for protected key storage. Consider an RP2350 or STM32 with secure-boot and key-storage features for a hardened design. | This analysis |

## Target C: Generic microcontroller

Define a minimum target profile rather than assuming every MCU is interchangeable.

| Resource/capability | Proposed minimum | Basis |
|---|---|---|
| RAM | 128 KB or more (keeps the 54 KB fast-signing strategy plus a 64 KB transport frame within budget) | Indicative Cortex-M4 figures above; token `MAX_FRAME` = 64 KiB |
| Flash | 256 KB or more for firmware plus credential storage | Assumption; measure once ported |
| CPU/clock | Cortex-M4/M33 class at 100 MHz or more preferred (DSP instructions help the NTT) | pqm4 targets |
| Hardware RNG or approved entropy source | Required: a documented TRNG with health tests | Security requirement |
| Protected key storage | Required for a hardened token: on-chip protected storage or a secure element | Threat model T-07 |
| USB support | USB device with CDC or HID | Transport design |
| Firmware verification/update | Secure boot plus signed updates with anti-rollback | Threat model T-10 |

## Target D: FPGA

Investigate at least two designs:

1. **Full token:** the FPGA-side system owns the key, randomness, ML-DSA implementation, and signing policy.
2. **Accelerator:** the host retains sensitive state while the FPGA accelerates selected arithmetic.

The full-token model better supports the requirement that the private key remain on hardware, but it requires secure key storage, trusted firmware/control logic, entropy, and side-channel protections.

| Question | Finding | Evidence |
|---|---|---|
| Operations worth accelerating | NTT/polynomial multiplication and SHAKE are the usual candidates; unmeasured for QuantumKey | Literature; open |
| Where the private key resides | Inside the token (full-token model), never on the host | Design decision: key-export-free migration |
| Randomness generation | On the device; source to be chosen | Architecture decision; open |
| Host-device protocol | The same framed `create` / `public` / `sign` structured protocol as the virtual token | `quantumkey/authenticator/token.py` |
| Expected latency benefit | Little on desktop: signing is about 3 ms of a ~325 ms login dominated by the vault KDF. A benefit is plausible only on slow MCUs. | `docs/evaluation/bench-2026-11-06.json` |
| Side-channel/fault risks | High and unassessed; FPGA implementations are not inherently resistant | Open |
| Development complexity | High; defer until an MCU token exists and a bottleneck is measured | Recommendation |

## Signing-backend implications

The future abstraction should allow software and hardware implementations to expose the same logical operations while avoiding assumptions that private-key bytes are always available to the desktop application.

Candidate concepts:

- algorithm/capability enumeration;
- key generation returning a public key plus an opaque key handle;
- signing by opaque key handle;
- public-key retrieval;
- device presence/status;
- explicit user authorization result;
- structured timing and error information;
- timeouts and cancellation;
- key deletion and device reset.

**Status (2026-11-06):** a first version is implemented as the `Signer` contract in `quantumkey/authenticator/core.py`. Keys are referenced by credential id (an opaque handle). Signing takes a *structured request* rather than raw bytes, and the signer builds the canonical message after checking the credential's policy. A real token would implement the same three commands (`create`, `public`, `sign`) over USB. Device status, cancellation, timing, deletion and reset are not yet in the contract.

