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

QuantumKey has a working research prototype on the `phase-3` branch. It meets the Phase 3 and 4 gates of [the plan](PHASES.md), most of Phase 5, and the Phase 8 gate in simulation (status per phase: [docs/MILESTONE_ACCEPTANCE.md](docs/MILESTONE_ACCEPTANCE.md)). It consists of a FastAPI relying party with atomic single-use challenges, a PIN-protected multi-credential vault, a software signer, a virtual token process, and a CLI. Registration, login and software-to-token credential migration work for ML-DSA-44/65/87, and replay, expiry, tampering, mismatch and concurrency cases are rejected in automated tests.

Candidate research contributions (structured-request signing, credential-bound signing policy, key-export-free migration) and their limits and prior art are in [docs/RESEARCH_NOTES.md](docs/RESEARCH_NOTES.md); the design is in [docs/superpowers/specs](docs/superpowers/specs/2026-11-06-policy-bound-migratable-credentials-design.md).

Run it (Windows, from the repository root, using the Phase 2 environment from [phase2/DEVELOPMENT.md](phase2/DEVELOPMENT.md)):

```powershell
$env:PATH = (Resolve-Path .\.venv\Scripts).Path + ';' + $env:PATH
python -m pytest -q
python -m uvicorn quantumkey.server.app:create_app --factory --port 8000
python -m quantumkey.server.admin invite alice    # prints a one-time invite, valid 24 h
python -m quantumkey.server.admin purge           # optional: the server also purges expired rows itself
python -m quantumkey.authenticator.cli --vault vault.sqlite3 register alice --invite <invite>
python -m quantumkey.authenticator.cli --vault vault.sqlite3 login alice
python -m quantumkey.authenticator.cli --vault vault.sqlite3 change-pin           # new PIN from QK_NEW_PIN or a prompt
python -m quantumkey.authenticator.cli --vault vault.sqlite3 delete <credential-id>
python -m quantumkey.bench --iterations 20
python -m quantumkey.authenticator.calibrate --target-ms 250 500   # Argon2id parameters for a target unlock time
```

Or on Linux in Docker, with liboqs built in Release mode:

```powershell
docker build -t quantumkey:dev .
docker run --rm quantumkey:dev                                    # full test suite
docker run --rm quantumkey:dev python -m quantumkey.bench --iterations 20
```

If your network or antivirus inspects HTTPS (for example Norton's Web Shield), the build cannot verify `github.com` or PyPI. Pass the inspecting root certificate as a build secret; it is used only by the download steps and is not stored in the image:

```powershell
docker build --secret id=extra_ca,src="C:\ProgramData\Norton\Antivirus\wscert.pem" -t quantumkey:dev .
```

To run the server tests against PostgreSQL 17, share the database container's network so it is on loopback, which the test guard in `tests/helpers.py` requires:

```bash
cid=$(docker run --rm -d -e POSTGRES_USER=qk_test_user -e POSTGRES_PASSWORD=qk_test_password -e POSTGRES_DB=qk_test_server postgres:17)
until docker exec "$cid" pg_isready -U qk_test_user -d qk_test_server; do sleep 1; done; sleep 2
docker run --rm --network "container:$cid" \
  -e QK_TEST_DATABASE_URL=postgresql+psycopg://qk_test_user:qk_test_password@127.0.0.1:5432/qk_test_server \
  quantumkey:dev python -m pytest tests/server -q
docker stop "$cid"
```

Read more:

- [System architecture](ARCHITECTURE.md)
- [Development phases](PHASES.md)
- [Phase 2 validation results and setup](phase2/README.md)

## Important limitation

QuantumKey is currently a research and educational prototype. It is not a certified security key, production authentication service, or drop-in replacement for WebAuthn.
