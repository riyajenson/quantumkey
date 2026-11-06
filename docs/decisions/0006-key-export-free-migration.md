# ADR 0006: Credential migration without key export

**Status:** Accepted
**Date:** 2026-11-06

## Decision

To move a credential to another signer or ML-DSA variant, the new signer generates a fresh key. The old credential signs a `migrate` message whose `extra` field is `migration_binding(new id, new algorithm, new public key, new policy hash)`. The new key signs a `register` proof over the same transaction. The server verifies both, then revokes the old credential and inserts the new one in a single database transaction.

## Rationale

Exporting a software key into hardware would mean the "hardware-backed" key once existed on the host, which defeats the purpose. Requiring the old key's authorization prevents an attacker from adding their own key to an account (T-05), and the proof of possession prevents binding a public key the client cannot use. Because the new algorithm is a parameter, the same mechanism doubles as algorithm rotation.

## Consequences

The old credential's policy must allow `migrate`, and a policy without it makes the credential non-migratable by design. A lost signer cannot be migrated from, so recovery needs a separate mechanism (for example a cold backup credential limited to `migrate`). The old vault row is not deleted automatically.
