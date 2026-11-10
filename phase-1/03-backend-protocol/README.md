# Phase 1 - Backend and Protocol

**Status:** Complete. Implemented in Phase 3 (`quantumkey/server`, `quantumkey/protocol`).

**Objective:** draft registration/login API contracts, the challenge lifecycle, the error model and trust boundaries.

| Deliverable | File |
|---|---|
| API contracts and error model | [`docs/API_CONTRACTS.md`](../../docs/API_CONTRACTS.md) |
| Canonical signed message | [`docs/decisions/0004-canonical-message.md`](../../docs/decisions/0004-canonical-message.md) |
| Structured request signing | [`docs/decisions/0005-structured-request-signing.md`](../../docs/decisions/0005-structured-request-signing.md) |
| Migration protocol | [`docs/decisions/0006-key-export-free-migration.md`](../../docs/decisions/0006-key-export-free-migration.md) |
| Trust boundaries | [`docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md) |

**Known limits:** no rate limiting and no authenticated first registration (`docs/RISK_REGISTER.md`, R-02, R-10).
