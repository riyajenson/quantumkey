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

What succeeded on the development machine (full commands in [`phase2/DEVELOPMENT.md`](../../phase2/DEVELOPMENT.md)):

1. **Native prerequisites:** Git and Visual Studio Build Tools with the C++ workload.
2. **Obtaining and building liboqs:** not done by hand. `pip install liboqs-python==0.16.0.1` (from `phase2/requirements.lock.txt`), then the first `import oqs` fetched liboqs 0.16.0 at commit `5a1a854b` and built it with the CMake from the virtual environment.
3. **Library produced:** `oqs.dll`, installed under the user's `_oqs` directory and reused by later environments.
4. **Search path:** the venv `Scripts` directory must be on `PATH` during the first import so the wrapper finds `cmake`. No manual DLL placement was needed.
5. **Wrapper installation:** from the pinned lock file into a fresh virtual environment.
6. **Import check:** `import oqs` and `oqs.get_enabled_sig_mechanisms()` list ML-DSA-44/65/87. The wrapper prints "liboqs-python faulthandler is disabled" to **stdout** on import. Anything that uses stdout as a protocol channel must redirect it (see `quantumkey/authenticator/token_entry.py`).
7. **Problems seen:** a build of several minutes for many unused algorithms, and the MSVC optimization-barrier/constant-time warning.
8. **WSL or Docker:** neither was tested.

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

**Current conclusion:** Validated with limitations (Windows 11 x64 only; Debug build; MSVC constant-time warning). See "Reproducibility notes" above.

