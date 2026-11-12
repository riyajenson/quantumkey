# ADR 0009: Credential-authorized enrollment and revocation

**Status:** Accepted
**Date:** 2026-11-12

## Context

An account had exactly one active credential: registration creates the account and migration replaces the credential. A revoke endpoint therefore had nothing to revoke, and the CLI's `delete` left a credential active on the server (FR-13). Letting a login session add or revoke devices would be simple, but it would let any session turn "add device, then revoke the old one" into a migration that the old credential's policy forbids, undermining credential-bound policy (ADR 0005).

## Decision

Account changes are signed, policy-checked operations of an existing credential, never bearer-session actions.

- **Enroll (operation 4).** The authorizing credential signs an `enroll` message whose `extra` is `migration_binding(new id, new algorithm, new public key, new policy hash)`; the operation byte keeps it distinct from `migrate`. The new key signs a `register` proof over the same transaction. The server verifies both, checks that the authorizer's stored policy allows `enroll`, and adds the new credential. The authorizer stays active.
- **Revoke (operation 5).** The authorizing credential signs a `revoke` message whose `extra` is `revocation_binding(target id)`, a length-prefixed SHA-256 of the target credential id. The server checks that the authorizer's policy allows `revoke`, that the target is an active credential of the same account, and that it is not the account's last active credential, then revokes it and ends its sessions. A credential may revoke itself if another remains.
- Policies may name `enroll` and `revoke`. The default policy for new credentials allows all five operations; existing credentials keep the policy they were sealed with.
- Revocation takes a lock on the account row first, so two concurrent revocations cannot leave an account with no active credential.

## Rationale

The signer builds both messages itself from a structured request (ADR 0005), so a host cannot obtain an `enroll` or `revoke` signature without the signer enforcing the credential's policy, and the virtual token enforces it out of process. A policy that omits `enroll` and `revoke` keeps a credential from changing the account at all. The lost-device case becomes: sign in on another enrolled device and revoke the lost one.

## Consequences

The canonical message format is unchanged; two operation values are added. Credentials created before this change cannot enroll or revoke (their sealed policy does not name the operations) until migrated to a policy that does. Enrollment means any one enrolled device whose policy allows `revoke` can remove the others, so devices are peers: the weakest enrolled device bounds the account's security.
