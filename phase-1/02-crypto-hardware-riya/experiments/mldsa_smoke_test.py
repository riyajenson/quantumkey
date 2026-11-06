"""Standalone ML-DSA feasibility experiment for QuantumKey Phase 1.

This is research code, not an authenticator implementation. It never prints or
writes private-key material. Run only with the official liboqs Python wrapper.
"""

from __future__ import annotations

import argparse
import json
import platform
import secrets
import statistics
import sys
import time
from typing import Any, Callable

try:
    import oqs
except ImportError as exc:
    raise SystemExit(
        "Could not import 'oqs'. Build/install liboqs and liboqs-python using "
        "the official Open Quantum Safe instructions."
    ) from exc


TARGETS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")


def percentile(values: list[float], fraction: float) -> float:
    """Return a nearest-rank percentile for a non-empty sample."""
    ordered = sorted(values)
    rank = max(1, int(len(ordered) * fraction + 0.999999999))
    return ordered[min(rank - 1, len(ordered) - 1)]


def summarize(samples_ms: list[float]) -> dict[str, float]:
    return {
        "mean_ms": statistics.fmean(samples_ms),
        "median_ms": statistics.median(samples_ms),
        "p95_ms": percentile(samples_ms, 0.95),
        "min_ms": min(samples_ms),
        "max_ms": max(samples_ms),
    }


def timed(operation: Callable[[], Any]) -> tuple[Any, float]:
    started = time.perf_counter_ns()
    result = operation()
    return result, (time.perf_counter_ns() - started) / 1_000_000


def library_version() -> str:
    for attribute in ("oqs_version", "version"):
        candidate = getattr(oqs, attribute, None)
        if callable(candidate):
            try:
                return str(candidate())
            except Exception:
                pass
    return "not exposed by this wrapper"


def run_variant(algorithm: str, iterations: int, challenge_size: int) -> dict[str, Any]:
    keygen_times: list[float] = []
    signing_times: list[float] = []
    verification_times: list[float] = []
    public_key_size = private_key_size = signature_size = 0

    for _ in range(iterations):
        with oqs.Signature(algorithm) as signer:
            public_key, keygen_ms = timed(signer.generate_keypair)
            private_key = signer.export_secret_key()
            challenge = secrets.token_bytes(challenge_size)
            signature, signing_ms = timed(lambda: signer.sign(challenge))
            valid, verification_ms = timed(
                lambda: signer.verify(challenge, signature, public_key)
            )
            if not valid:
                raise RuntimeError(f"valid signature rejected for {algorithm}")

            changed_message = bytes([challenge[0] ^ 1]) + challenge[1:]
            if signer.verify(changed_message, signature, public_key):
                raise RuntimeError(f"modified message accepted for {algorithm}")

            changed_signature = bytes([signature[0] ^ 1]) + signature[1:]
            if signer.verify(challenge, changed_signature, public_key):
                raise RuntimeError(f"modified signature accepted for {algorithm}")

            keygen_times.append(keygen_ms)
            signing_times.append(signing_ms)
            verification_times.append(verification_ms)
            public_key_size = len(public_key)
            private_key_size = len(private_key)
            signature_size = len(signature)

            # Remove references as soon as this iteration is complete. Python
            # cannot guarantee secure memory zeroization; document that limit.
            del private_key, signature, challenge

    return {
        "algorithm": algorithm,
        "iterations": iterations,
        "public_key_bytes": public_key_size,
        "private_key_bytes": private_key_size,
        "signature_bytes": signature_size,
        "key_generation": summarize(keygen_times),
        "signing": summarize(signing_times),
        "verification": summarize(verification_times),
        "negative_tests": {
            "modified_message_rejected": True,
            "modified_signature_rejected": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--challenge-bytes", type=int, default=32)
    parser.add_argument("--algorithm", choices=TARGETS, action="append")
    args = parser.parse_args()
    if args.iterations < 1 or args.challenge_bytes < 1:
        parser.error("iterations and challenge-bytes must be positive")

    enabled = set(oqs.get_enabled_sig_mechanisms())
    requested = tuple(args.algorithm or TARGETS)
    unavailable = [name for name in requested if name not in enabled]

    report: dict[str, Any] = {
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python": sys.version,
            "liboqs": library_version(),
        },
        "enabled_mldsa_mechanisms": sorted(
            name for name in enabled if "ML-DSA" in name
        ),
        "unavailable_requested_mechanisms": unavailable,
        "challenge_bytes": args.challenge_bytes,
        "results": [],
    }

    for algorithm in requested:
        if algorithm in enabled:
            report["results"].append(
                run_variant(algorithm, args.iterations, args.challenge_bytes)
            )

    print(json.dumps(report, indent=2))
    return 1 if unavailable else 0


if __name__ == "__main__":
    raise SystemExit(main())

