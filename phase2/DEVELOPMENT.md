# Phase 2 Development Environment

## Validated machine

The recorded run used Windows 11 (x64), Python 3.12.10, an Intel Core Ultra 5 125H, 15.4 GiB RAM, CMake 4.4.4, Visual Studio Build Tools 18, MSVC 19.51.36260, and Windows SDK 10.0.26100.0.

Python packages are pinned in [`requirements.lock.txt`](requirements.lock.txt). The liboqs wrapper was `liboqs-python==0.16.0.1`; it fetched and built liboqs 0.16.0 at commit `5a1a854b0dc9f2141bdc771c555ee60c37950183` during its first import. The generated native build used the Visual Studio Debug configuration.

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

## Reproducibility limitations

- This exact setup has been exercised only on Windows 11 x64. Linux and macOS commands have not been validated in this repository.
- The wrapper fetched the liboqs source revision above. A clean setup needs network access for that checkout and build.
- The automatically generated MSVC build warns that liboqs cannot guarantee its optimization barrier for unsupported toolchains and that non-constant-time behavior may occur. Treat the run as functional compatibility evidence only, not a security assurance or production recommendation.
- The benchmark used the default Visual Studio Debug configuration. The measurements are suitable for a local comparison across variants, not a release-performance claim.
- PostgreSQL could not be tested: Docker CLI 29.7.2 is installed, but `docker info` cannot connect to `npipe:////./pipe/dockerDesktopLinuxEngine` because the Docker Desktop Linux engine is not running. No local PostgreSQL client or service is installed. PostgreSQL selection remains open until an E2E run is possible.
