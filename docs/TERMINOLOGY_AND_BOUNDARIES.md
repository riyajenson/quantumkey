# Terminology and Security Boundaries

**Status:** Phase 1 baseline, reconciled with the prototype on 2026-11-06.

## 1. Purpose

Fix the meaning of terms used across QuantumKey and keep product, protocol and security claims within what the design and code support.

## 2. Terms

| Term | Meaning in QuantumKey | Boundary / caution |
|---|---|---|
| QuantumKey | Research prototype of a post-quantum, WebAuthn-inspired authenticator | A project name, not a certification or proof of quantum resistance |
| ML-DSA | NIST FIPS 204 lattice signature scheme (from CRYSTALS-Dilithium); variants 44/65/87, default 65 | A signature scheme, not encryption. Provided by liboqs 0.16.0, never implemented here |
| Relying party (RP) | The server that issues challenges, stores public keys and verifies signatures (`quantumkey/server`) | Identified by `rp_id` (default `quantumkey.local`) |
| Credential | ML-DSA key pair + credential id + signing policy, bound to one account and one RP | Not a password and not an account |
| Signing policy | Canonical JSON (RP, allowed operations, expiry, rate limit) whose SHA-256 is bound into every signed message | Enforced by the signer; RP, operations and expiry are re-checked by the server |
| Signer | Component holding private keys and producing signatures through the `Signer` contract (`quantumkey/authenticator/core.py`) | Two implementations: software signer and virtual token |
| Structured-request signing | The signer accepts a description of an operation, never raw bytes, and builds the canonical message itself | Protects only when the signer is separated from the host (token) |
| Software signer | Signer backed by the encrypted vault, running in the host process | Same process as the host: offers no protection against host malware |
| Virtual token | Separate process speaking the framed token protocol, keys in its memory only | A process boundary that simulates a device interface. Not tamper resistant, not persistent |
| Vault | Local SQLite file with Argon2id + AES-256-GCM sealed private keys | Protects data at rest only |
| Challenge | 32 random bytes plus transaction id, purpose, account, expiry (60 s) and single-use state | Consumed atomically before verification |
| Canonical signed message | `QuantumKey/v1\0` domain tag, operation byte, then length-prefixed fields (`quantumkey/protocol/message.py`) | The server always rebuilds it from its own records |
| Migration | Old credential authorizes a new credential created in another signer; old is revoked atomically | No private key is exported |
| User presence / verification | Not yet implemented. The PIN unlocks the vault but is not a protocol-level UV flag | Must not be claimed |
| WebAuthn | W3C API and ecosystem | QuantumKey is not WebAuthn or CTAP compatible |

## 3. Claims QuantumKey may make (supported by code and tests)

- It authenticates with ML-DSA signatures over a canonical, versioned, domain-separated message, with expiring single-use challenges.
- The server stores public keys only; private keys stay in the vault or the token.
- Credentials carry a signing policy bound into every signature, and swapping it is detected.
- A credential can be migrated to a different signer or ML-DSA variant without exporting a private key.

## 4. Claims QuantumKey must not make

- Drop-in compatibility with WebAuthn, FIDO2, browsers or any third-party service.
- "Quantum-proof", unbreakable, certified, tamper-proof, or side-channel resistant.
- That the vault protects a key while the host is compromised and the vault unlocked.
- That the virtual token is hardware, or that any general-purpose MCU isolates keys by itself.
- That the candidate contributions are novel before a full prior-art review (see `docs/RESEARCH_NOTES.md`).

## 5. Trust boundaries

1. **Network (client to RP):** untrusted. TLS is required in deployment but not configured in the prototype.
2. **RP server and database:** trusted to issue challenges and verify, and may be compromised independently. They hold no private keys.
3. **Host and CLI process:** may be compromised. With the software signer it can use or extract unlocked keys.
4. **Host to token transport:** untrusted input to the token. Frames are bounded (64 KiB) and strictly parsed, with unknown fields rejected.
5. **Token process:** enforces policy and builds messages itself. Its isolation is only as strong as OS process separation.
6. **Vault file:** may be copied, modified or rolled back. AEAD detects modification but not rollback.
7. **User:** enters the PIN. There is no trusted display, so the user cannot confirm which RP a signature is for.
