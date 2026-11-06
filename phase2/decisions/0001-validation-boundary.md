# ADR 0001: Keep Phase 2 experiments outside the application

**Status:** Accepted for Phase 2
**Date:** 2026-10-26

## Decision

Keep the API, database, vault, and signing implementations under `phase2/` as isolated technology-validation code. Phase 2 proves that the selected libraries interoperate through a real HTTP flow; Phase 3 will define and build the actual server protocol and application data model.

## Rationale

The repository has architecture and research documents but no application foundation. Building a production service here would collapse the boundary between technical validation and the separately scoped Phase 3 protocol/backend work.

## Consequences

The validation service deliberately omits account binding, challenge expiry, replay protection, authentication, migration tooling, TLS, and production hardening. Its interface is disposable and must not be used as an authentication server.
