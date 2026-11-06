# QuantumKey

QuantumKey is a research prototype for a **post-quantum software authenticator**. In simple terms, it is a virtual security key that lives on a user's computer and proves a login using cryptography instead of sending a reusable password to a server.

The project is inspired by WebAuthn and passkeys, but it is not intended to be a fully standards-compliant WebAuthn authenticator in its first version.

## The idea

QuantumKey creates two related cryptographic keys for a user and service:

- The **private key** stays inside the authenticator and is encrypted locally.
- The **public key** is registered with the authentication server.

During login, the server sends a new random challenge. QuantumKey unlocks the appropriate private key after local user authorization, signs the challenge, and returns only the signature. The server verifies that signature with the stored public key.

```text
Server creates a one-time challenge
                 |
                 v
QuantumKey signs it with the private key
                 |
                 v
Server verifies it with the public key
                 |
                 v
        Login succeeds or fails
```

The private key must never be sent to or stored by the server.

## Why post-quantum?

QuantumKey is designed to use **ML-DSA**, the post-quantum digital-signature standard defined by NIST in FIPS 204. ML-DSA is intended to resist attacks from both classical and future quantum computers.

The project will use the Open Quantum Safe `liboqs` implementation through `liboqs-python`. QuantumKey will not implement ML-DSA itself.

## Main parts

1. **FastAPI authentication server** - registers public keys, creates short-lived challenges, prevents replay, and verifies signatures.
2. **QuantumKey authenticator** - creates keys, protects the local vault with a PIN, manages credentials, approves requests, and signs challenges.
3. **Signing backend** - separates the authentication workflow from the place where signing happens.
4. **Future hardware token** - may later perform signing through USB Serial or USB HID without requiring the server protocol to be redesigned.

The first authenticator will be command-line based. A PySide6 desktop interface will be added only after the authentication and vault layers are stable.

## First important milestone

```text
ML-DSA key generation
        +
server-generated challenge
        +
local signing
        +
server-side verification
        =
successful authentication
```

## Planned capabilities

- ML-DSA key generation, signing, and verification
- Registration and challenge-response login
- Expiring, single-use challenges
- Encrypted local private-key storage
- PIN protection
- Multiple credentials and services
- Device identity and credential management
- Replaceable software and hardware signing backends
- Performance, size, storage, and network benchmarking

## Security principles

- Private keys never leave the authenticator.
- Private keys and PINs are never stored or logged in plaintext.
- The server stores public keys only.
- Challenges are generated with secure randomness, expire quickly, and can be used once.
- Cryptographic primitives are provided by established libraries.
- Signing operations are bound to the intended user, credential, service, and protocol operation.

## Project status

QuantumKey has a working research prototype on the `phase-3` branch covering Phases 3 to 7 of [the plan](PHASES.md): a FastAPI relying party with atomic single-use challenges, a PIN-protected multi-credential vault, a software signer, a virtual token process, and a CLI. Registration, login and software-to-token credential migration work for ML-DSA-44/65/87, and replay, expiry, tampering, mismatch and concurrency cases are rejected in automated tests.

Candidate research contributions (structured-request signing, credential-bound signing policy, key-export-free migration) and their limits and prior art are in [docs/RESEARCH_NOTES.md](docs/RESEARCH_NOTES.md); the design is in [docs/superpowers/specs](docs/superpowers/specs/2026-11-06-policy-bound-migratable-credentials-design.md).

Run it (Windows, from the repository root, using the Phase 2 environment from [phase2/DEVELOPMENT.md](phase2/DEVELOPMENT.md)):

```powershell
$env:PATH = (Resolve-Path .\.venv\Scripts).Path + ';' + $env:PATH
python -m pytest -q
python -m uvicorn quantumkey.server.app:create_app --factory --port 8000
python -m quantumkey.authenticator.cli --vault vault.sqlite3 register alice
python -m quantumkey.authenticator.cli --vault vault.sqlite3 login alice
python -m quantumkey.bench --iterations 20
```

Read more:

- [System architecture](ARCHITECTURE.md)
- [Development phases](PHASES.md)
- [Phase 2 validation results and setup](phase2/README.md)

## Important limitation

QuantumKey is currently a research and educational prototype. It is not a certified security key, production authentication service, or drop-in replacement for WebAuthn.
