"""Experiment E-04: calibrate the vault's Argon2id parameters to a target unlock time.

Times one key derivation for each parameter set in a grid and, for each target,
recommends the set with the most work (passes x memory) whose median fits.
Results describe the machine that ran them.

    python -m quantumkey.authenticator.calibrate --target-ms 250 500 --json report.json

Apply a recommendation to an existing vault's credentials with
`cli change-pin --time-cost T --memory-kib M --parallelism P` (the new PIN may
equal the old one).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import time
from dataclasses import asdict
from typing import Callable

from quantumkey.authenticator.vault import DEFAULT_KDF, KdfParams, _derive

# Memory sizes: 19 MiB and 46 MiB (OWASP's minimum Argon2id settings use them),
# 64 MiB (the current default) and 128 MiB.
DEFAULT_GRID = [
    KdfParams(time_cost, memory_kib, 1)
    for memory_kib in (19_456, 47_104, 65_536, 131_072)
    for time_cost in (1, 2, 3, 4)
]


def measure_kdf(kdf: KdfParams, repeats: int) -> float:
    """Median milliseconds for one derivation with `kdf`."""
    samples = []
    for _ in range(repeats):
        salt = os.urandom(16)
        start = time.perf_counter()
        _derive("calibration-pin", salt, kdf)
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples)


def measure_grid(
    grid: list[KdfParams], repeats: int, measure: Callable[[KdfParams, int], float] | None = None
) -> list[tuple[KdfParams, float]]:
    measure = measure or measure_kdf
    return [(kdf, measure(kdf, repeats)) for kdf in grid]


def recommend(table: list[tuple[KdfParams, float]], target_ms: float) -> KdfParams | None:
    fitting = [kdf for kdf, ms in table if ms <= target_ms]
    if not fitting:
        return None
    return max(fitting, key=lambda k: (k.time_cost * k.memory_kib, k.memory_kib))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="quantumkey-calibrate")
    parser.add_argument("--target-ms", type=float, nargs="+", default=[250.0, 500.0])
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--json", help="write the full report to this file")
    args = parser.parse_args(argv)

    table = measure_grid(DEFAULT_GRID, args.repeats, measure_kdf)
    print("time_cost  memory_MiB  median_ms")
    for kdf, ms in table:
        marker = "  (current default)" if kdf == DEFAULT_KDF else ""
        print(f"{kdf.time_cost:>9}  {kdf.memory_kib / 1024:>10.0f}  {ms:>9.1f}{marker}")
    recommendations = {}
    for target in args.target_ms:
        choice = recommend(table, target)
        key = f"{target:g}"
        recommendations[key] = asdict(choice) if choice else None
        print(f"target {key} ms: {choice if choice else 'nothing fits'}")
    if args.json:
        report = {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "repeats": args.repeats,
            "measurements": [{**asdict(kdf), "median_ms": round(ms, 1)} for kdf, ms in table],
            "recommendations": recommendations,
        }
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
