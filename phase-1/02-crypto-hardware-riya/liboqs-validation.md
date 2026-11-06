# liboqs and liboqs-python Validation

## Purpose

Establish that the Open Quantum Safe stack supplies the operations QuantumKey requires and document a reproducible development setup.

## Environment record

Fill every field. Use exact versions or Git commit hashes rather than “latest.”

| Item | Value |
|---|---|
| Test date | TBD |
| Operating system and edition | TBD |
| OS architecture | TBD |
| CPU | TBD |
| Installed RAM | TBD |
| Python version | TBD |
| Compiler/toolchain | TBD |
| CMake version | TBD |
| liboqs version/commit | TBD |
| liboqs-python version/commit | TBD |
| Build type and flags | TBD |
| OpenSSL version, if used | TBD |

## Installation procedure

Document the exact commands that succeeded on the development machine. Include:

1. native prerequisites;
2. how `liboqs` was obtained and built;
3. whether a shared library/DLL was produced;
4. how the library was placed on the runtime search path;
5. how `liboqs-python` was installed;
6. how the Python import was verified;
7. any Windows DLL, compiler, PATH, or architecture problems;
8. whether WSL or Docker was tested as an alternative.

Do not paste secrets, user tokens, or machine-specific private paths that other team members cannot use.

## Capability checklist

- [ ] `import oqs` succeeds.
- [ ] Runtime/library version information is captured.
- [ ] Enabled signature mechanisms are enumerated.
- [ ] `ML-DSA-44` is enabled.
- [ ] `ML-DSA-65` is enabled.
- [ ] `ML-DSA-87` is enabled.
- [ ] A keypair can be generated for every enabled target variant.
- [ ] The private key can be exported for encrypted vault storage.
- [ ] A signature can be created.
- [ ] The correct message/signature/public-key tuple verifies.
- [ ] A modified message is rejected.
- [ ] A modified signature is rejected.
- [ ] Context-string signing and verification behavior is tested or documented.
- [ ] Errors and exceptions are documented without logging secret material.

## Expected Python surface

The official wrapper exposes the `oqs.Signature` class and runtime enumeration functions such as `oqs.get_enabled_sig_mechanisms()`. Verify the actual signatures against the installed wrapper rather than relying on copied examples.

Recent liboqs-python releases provide FIPS 204 context-string methods named `sign_with_ctx_str` and `verify_with_ctx_str`. Record whether they exist in the tested version and decide later whether QuantumKey should use an ML-DSA context string in addition to protocol-level domain separation.

## Compatibility findings

### Works

TBD

### Fails or needs manual setup

TBD

### Reproducibility notes

TBD

## Validation conclusion

Choose one after testing:

- **Validated:** all required operations work reproducibly.
- **Validated with limitations:** core operations work, but setup or platform limitations remain.
- **Not validated:** a blocking capability is unavailable or unreliable.

**Current conclusion:** TBD

