# Phase 2 Development Environment

## Validated machine

The recorded run used Windows 11 (x64), Python 3.12.10, an Intel Core Ultra 5 125H, 15.4 GiB RAM, CMake 4.4.4, Visual Studio Build Tools 18, MSVC 19.51.36260, and Windows SDK 10.0.26100.0.

Python packages are pinned in [`requirements.lock.txt`](requirements.lock.txt). The liboqs wrapper was `liboqs-python==0.16.0.1`; it fetched and built liboqs 0.16.0 at commit `5a1a854b0dc9f2141bdc771c555ee60c37950183` during its first import. The generated native build used the Visual Studio Debug configuration.

The PostgreSQL E2E run used PostgreSQL 17.11 from image `postgres:17@sha256:b8faeff7712663c2773a190181e1246e37e364b887611c04658c28b44e2408fe`, with Psycopg 3.3.6 and its binary extra.

## Windows setup

Install Git and Visual Studio Build Tools with the C++ workload. Then, from the repository root, run:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r phase2\requirements.lock.txt
$env:PATH = (Resolve-Path .\.venv\Scripts).Path + ';' + $env:PATH
.\.venv\Scripts\python.exe -m pytest -q
```

The `PATH` update is required for the first import: `liboqs-python` invokes the CMake executable installed in the virtual environment's `Scripts` directory. Activating the environment with `.\.venv\Scripts\Activate.ps1` before the test command has the same effect.

The locked Python environment and E2E suite were also rerun in a fresh virtual environment. That run reused the previously built liboqs installation under the user's `_oqs` directory; the native build itself was verified separately on the same machine.

On first import, `liboqs-python` builds the matching liboqs release and installs it under the user's local `_oqs` directory. The first run can take several minutes. Later runs reuse that native library. To reproduce the recorded measurement ranges, run the 100-iteration ML-DSA benchmark three times sequentially:

```powershell
$env:PATH = (Resolve-Path .\.venv\Scripts).Path + ';' + $env:PATH
.\.venv\Scripts\python.exe phase-1\02-crypto-hardware-riya\experiments\mldsa_smoke_test.py --iterations 100
```

The experiment prints JSON and does not write keys or benchmark artifacts. Review the output before saving it.

## PostgreSQL E2E

Start Docker Desktop's Linux engine, install the locked dependencies, and run:

```powershell
.\phase2\run_postgres_e2e.ps1
```

If the environment uses a differently named virtual environment, pass its Python executable:

```powershell
.\phase2\run_postgres_e2e.ps1 -PythonPath '.\.venv-phase2-repro\Scripts\python.exe'
```

The script creates an isolated PostgreSQL container on a temporary loopback port, runs the complete HTTP E2E suite, and removes that container in a `finally` block. It generates a throwaway database password at runtime and restores the calling shell's test-only database URL and PATH after the run. Ordinary `pytest` runs ignore `QK_DATABASE_URL` and use per-test SQLite files; PostgreSQL requires the separate, validated `QK_TEST_DATABASE_URL` opt-in.

## Reproducibility limitations

- This exact setup has been exercised only on Windows 11 x64. Linux and macOS commands have not been validated in this repository.
- The wrapper fetched the liboqs source revision above. A clean setup needs network access for that checkout and build.
- The automatically generated MSVC build warns that liboqs cannot guarantee its optimization barrier for unsupported toolchains and that non-constant-time behavior may occur. Treat the run as functional compatibility evidence only, not a security assurance or production recommendation.
- The benchmark used the default Visual Studio Debug configuration. The measurements are suitable for a local comparison across variants, not a release-performance claim.
- PostgreSQL testing requires the Docker Desktop Linux engine. The PostgreSQL E2E script reports a clear error if Docker is unavailable and only stops the temporary container it created.
