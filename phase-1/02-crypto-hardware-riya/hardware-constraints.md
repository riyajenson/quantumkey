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
| Does liboqs build natively? | TBD | TBD |
| Are all ML-DSA variants enabled? | TBD | TBD |
| Peak signing memory | TBD | TBD |
| Signing latency | TBD | TBD |
| Shared-library/deployment requirements | TBD | TBD |
| Suitable for first hardware-like prototype? | TBD | TBD |

## Target B: Raspberry Pi Pico / RP2040

The RP2040 is substantially more constrained than a Linux Raspberry Pi. Treat them as different target classes.

| Question | Finding | Evidence |
|---|---|---|
| Available SRAM and flash | TBD | Vendor documentation |
| Compatible portable ML-DSA implementation | TBD | TBD |
| Peak signing RAM/stack | TBD | Measurement or primary source |
| Estimated signing latency | TBD | Measurement or primary source |
| Secure randomness source | TBD | TBD |
| Protected nonvolatile key storage | TBD | TBD |
| USB Serial/HID feasibility | TBD | TBD |
| Overall classification | TBD | Feasible / uncertain / unsuitable |

## Target C: Generic microcontroller

Define a minimum target profile rather than assuming every MCU is interchangeable.

| Resource/capability | Proposed minimum | Basis |
|---|---|---|
| RAM | TBD | TBD |
| Flash | TBD | TBD |
| CPU/clock | TBD | TBD |
| Hardware RNG or approved entropy source | Required; details TBD | Security requirement |
| Protected key storage | TBD | Threat model |
| USB support | TBD | Transport design |
| Firmware verification/update | TBD | Lifecycle requirement |

## Target D: FPGA

Investigate at least two designs:

1. **Full token:** the FPGA-side system owns the key, randomness, ML-DSA implementation, and signing policy.
2. **Accelerator:** the host retains sensitive state while the FPGA accelerates selected arithmetic.

The full-token model better supports the requirement that the private key remain on hardware, but it requires secure key storage, trusted firmware/control logic, entropy, and side-channel protections.

| Question | Finding | Evidence |
|---|---|---|
| Operations worth accelerating | TBD | TBD |
| Where the private key resides | TBD | Architecture decision |
| Randomness generation | TBD | Architecture decision |
| Host-device protocol | TBD | Phase 1 requirement only |
| Expected latency benefit | TBD | TBD |
| Side-channel/fault risks | TBD | TBD |
| Development complexity | TBD | TBD |

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

The final interface will be designed in a later phase.

