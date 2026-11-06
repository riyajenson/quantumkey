# Phase 1 - Authenticator and Vault

**Status:** Complete. Implemented in `quantumkey/authenticator`.

**Objective:** define the vault, PIN, device identity, credential lifecycle and user-interaction requirements.

| Deliverable | File |
|---|---|
| Vault format, KDF, AAD, lifecycle | [`docs/VAULT_SPECIFICATION.md`](../../docs/VAULT_SPECIFICATION.md) |
| Signing backend contract | [`phase2/decisions/0002-signing-backend-contract.md`](../../phase2/decisions/0002-signing-backend-contract.md) (superseded by ADR 0005) |
| Virtual token boundary | [`docs/decisions/0005-structured-request-signing.md`](../../docs/decisions/0005-structured-request-signing.md) |

**Known limits:** device identity, controlled unlocked sessions and a CLI credential-deletion command are not built (`docs/MILESTONE_ACCEPTANCE.md`, Phase 5).
