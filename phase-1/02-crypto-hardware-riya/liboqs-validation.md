# liboqs and liboqs-python Validation

## Purpose

Establish that the Open Quantum Safe stack supplies the operations QuantumKey requires and document a reproducible development setup.

## Environment record

Fill every field. Use exact versions or Git commit hashes rather than “latest.”

| Item | Value |
|---|---|
| Test date | 2026-10-26 |
| Operating system and edition | Windows 11, build 26200 |
| OS architecture | AMD64 / x64 |
| CPU | Intel Core Ultra 5 125H |
| Installed RAM | 15.4 GiB |
| Python version | 3.12.10 |
| Compiler/toolchain | Visual Studio Build Tools 18, MSVC 19.51.36260, Windows SDK 10.0.26100.0 |
| CMake version | 4.4.4 |
| liboqs version/commit | 0.16.0 / `5a1a854b0dc9f2141bdc771c555ee60c37950183` |
| liboqs-python version/commit | 0.16.0.1 (PyPI release) |
| Build type and flags | Visual Studio Debug configuration; default liboqs options |
| OpenSSL version, if used | Not separately configured for this build |

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

- [x] `import oqs` succeeds.
- [x] Runtime/library version information is captured.
- [x] Enabled signature mechanisms are enumerated.
- [x] `ML-DSA-44` is enabled.
- [x] `ML-DSA-65` is enabled.
- [x] `ML-DSA-87` is enabled.
- [x] A keypair can be generated for every enabled target variant.
- [x] The private key can be exported for encrypted vault storage.
- [x] A signature can be created.
- [x] The correct message/signature/public-key tuple verifies.
- [x] A modified message is rejected.
- [x] A modified signature is rejected.
- [x] Context-string method names are present; behavior is explicitly left untested.
- [x] Errors are documented without printing secret material; wrong-key/context exception mapping remains for later integration.

## Expected Python surface

The official wrapper exposes the `oqs.Signature` class and runtime enumeration functions such as `oqs.get_enabled_sig_mechanisms()`. Verify the actual signatures against the installed wrapper rather than relying on copied examples.

Recent liboqs-python releases provide FIPS 204 context-string methods named `sign_with_ctx_str` and `verify_with_ctx_str`. Record whether they exist in the tested version and decide later whether QuantumKey should use an ML-DSA context string in addition to protocol-level domain separation.

## Compatibility findings

### Works

The pinned wrapper install succeeded in a disposable Python virtual environment. On first import it fetched the matching liboqs source, generated `oqs.dll`, and installed the library. All three standardized ML-DSA mechanisms were enabled. The 100-iteration experiment passed valid verification and rejected modified messages and signatures for every variant. The complete environment and results are recorded in [`phase2/DEVELOPMENT.md`](../../phase2/DEVELOPMENT.md) and [`phase2/VALIDATION_RESULTS.md`](../../phase2/VALIDATION_RESULTS.md).

### Fails or needs manual setup

No WSL or Docker setup was tested. MSVC emitted a liboqs warning that an optimization barrier cannot be guaranteed on this toolchain; the build is suitable only for functional compatibility validation. The default build compiled many unrelated algorithms and took several minutes. Cross-platform build reproducibility, a release configuration, PostgreSQL, and a constant-time-approved compiler/build remain open.

### Reproducibility notes

Validated with limitations. The libraries provide the required functional key-generation, private-key export, signing, and verification operations for all three variants. The Windows Debug build and MSVC timing-safety warning prevent security assurance or final performance claims; follow-up validation must use a supported constant-time build setup and a release configuration.

## Validation conclusion

Choose one after testing:

- **Validated:** all required operations work reproducibly.
- **Validated with limitations:** core operations work, but setup or platform limitations remain.
- **Not validated:** a blocking capability is unavailable or unreliable.

**Current conclusion:** TBD

