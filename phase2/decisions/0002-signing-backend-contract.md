# ADR 0002: Draft software signing-backend contract

**Status:** Provisional
**Date:** 2026-10-26

## Decision

Use a small Python `Protocol` for Phase 2 experiments with three operations: generate a keypair, sign bytes, and verify bytes. Keep liboqs-specific calls inside `SoftwareMLDSABackend`.

## Rationale

The end-to-end experiment can exercise cryptography without coupling the API service to liboqs object construction. This makes algorithm enumeration and the provider replaceable in later application layers.

## Consequences and follow-up

The experimental interface passes private-key bytes between the vault and software backend so the encryption and signing path can be validated. The architecture target remains an opaque key handle; the Phase 3/5 application contract must avoid exposing private bytes to higher-level flows and must define structured errors, cancellation, device status, and operation timing.
