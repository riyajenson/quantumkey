# ADR 0008: Keep the Argon2id default at 3 passes and 64 MiB

**Status:** Accepted
**Date:** 2026-11-12

## Decision

New vault credentials keep Argon2id with time cost 3, 64 MiB of memory and parallelism 1. Deployments that want a different unlock time run `python -m quantumkey.authenticator.calibrate` on their target machine and apply the result with `cli change-pin --time-cost T --memory-kib M`.

## Rationale

The setting matches the memory and pass count of RFC 9106's second recommended Argon2id option (3 passes, 64 MiB) and is well above OWASP's minimums (19 MiB with 2 passes, or 46 MiB with 1). Measured unlock time is 129 ms on the CI runner and about 256 ms on the Windows development machine (E-04), within a 250-500 ms interactive budget. The calibration recommended 128 MiB with 2 passes for a 250 ms budget on the CI runner, but doubling memory hurts on constrained machines: the development machine had 0.8 GiB free during E-04, where 128 MiB derivations slowed erratically. Unlocked sessions already remove the unlock from repeated signatures, so raising the default buys little at a real cost.

## Consequences

Offline guessing against a stolen vault file costs one 64 MiB, 3-pass Argon2id derivation per PIN guess; a short PIN remains weak (T-06). Each credential records its own parameters (vault format v3), so a later default change applies to new credentials and to any vault re-wrapped with `change-pin`.
