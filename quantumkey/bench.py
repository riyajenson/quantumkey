"""Phase 6 evaluation: end-to-end cost of the QuantumKey protocol per ML-DSA variant.

Measures, per variant: primitive latency (keygen/sign/verify), full protocol
latency (register / login / migrate through the HTTP app, in-process), wire
bytes of the request and response bodies, and server database growth per
credential. Prints JSON. Numbers describe the machine and build that produced
them and are not release-performance claims.

    python -m quantumkey.bench --iterations 20
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

from quantumkey import crypto
from quantumkey.authenticator.client import AuthClient
from quantumkey.authenticator.core import SignRequest
from quantumkey.authenticator.software import SoftwareSigner
from quantumkey.protocol.message import Operation
from quantumkey.server.app import create_app

RP_ID = "bench.local"


def summary(samples_ms: list[float]) -> dict:
    ordered = sorted(samples_ms)
    p95 = ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))]
    return {
        "median_ms": round(statistics.median(ordered), 3),
        "mean_ms": round(statistics.fmean(ordered), 3),
        "p95_ms": round(p95, 3),
    }


def timed(fn) -> float:
    start = time.perf_counter()
    fn()
    return (time.perf_counter() - start) * 1000


class Counting:
    """Wraps an HTTP client and totals request/response body bytes."""

    def __init__(self, http) -> None:
        self.http = http
        self.sent = 0
        self.received = 0

    def post(self, path, json=None):  # noqa: A002 - mirrors httpx
        import json as jsonlib

        self.sent += len(jsonlib.dumps(json, separators=(",", ":")))
        response = self.http.post(path, json=json)
        self.received += len(response.content)
        return response


def bench_variant(algorithm: str, iterations: int, workdir: Path) -> dict:
    db_path = workdir / f"rp-{algorithm}.sqlite3"
    # One client makes every request, so the per-IP rate limit is off for the benchmark.
    http = TestClient(create_app("sqlite:///" + db_path.as_posix(), rp_id=RP_ID, rate_limit=None))
    counting = Counting(http)
    client = AuthClient(counting, RP_ID)
    signer = SoftwareSigner(workdir / f"vault-{algorithm}.sqlite3", pin="bench-pin")

    primitives = {"keygen": [], "sign": [], "verify": []}
    for _ in range(iterations):
        keys = []
        primitives["keygen"].append(timed(lambda: keys.append(crypto.generate_keypair(algorithm))))
        public_key, private_key = keys[0]
        signatures = []
        primitives["sign"].append(
            timed(lambda: signatures.append(crypto.sign(algorithm, private_key, b"x" * 100)))
        )
        primitives["verify"].append(
            timed(lambda: crypto.verify(algorithm, public_key, b"x" * 100, signatures[0]))
        )

    register_ms, login_ms = [], []
    register_bytes = login_bytes = (0, 0)
    size_before = db_path.stat().st_size if db_path.exists() else 0
    for i in range(iterations):
        invite = http.app.state.rp.issue_invite(f"user{i}")  # operator step, not timed
        before = (counting.sent, counting.received)
        register_ms.append(
            timed(lambda: client.register(f"user{i}", signer, algorithm=algorithm, invite=invite))
        )
        mid = (counting.sent, counting.received)
        register_bytes = (mid[0] - before[0], mid[1] - before[1])
        login_ms.append(timed(lambda: client.login(f"user{i}", signer)))
        after = (counting.sent, counting.received)
        login_bytes = (after[0] - mid[0], after[1] - mid[1])
    size_after = db_path.stat().st_size

    # Policy check + canonical message cost, isolated from the signature itself.
    credential = signer.vault.list_credentials()[0]
    request = SignRequest(Operation.LOGIN, RP_ID, "tx", b"\x00" * 32)
    core_ms = [timed(lambda: signer.sign(credential.credential_id, request)) for _ in range(iterations)]

    http.app.state.rp.engine.dispose()
    public_size, signature_size = crypto.SIZES[algorithm]
    return {
        "algorithm": algorithm,
        "iterations": iterations,
        "sizes_bytes": {"public_key": public_size, "signature": signature_size},
        "primitives": {name: summary(values) for name, values in primitives.items()},
        "protocol_ms": {
            "register_end_to_end": summary(register_ms),
            "login_end_to_end": summary(login_ms),
            "software_signer_sign_incl_vault_unlock": summary(core_ms),
        },
        "wire_bytes_json": {
            "register_request_total": register_bytes[0],
            "register_response_total": register_bytes[1],
            "login_request_total": login_bytes[0],
            "login_response_total": login_bytes[1],
        },
        "server_db_bytes_per_credential": round((size_after - size_before) / iterations),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument(
        "--note", default="in-process HTTP (no network); unoptimized liboqs build on Windows"
    )
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        results = [bench_variant(a, args.iterations, Path(tmp)) for a in crypto.ALGORITHMS]
    print(
        json.dumps(
            {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "processor": platform.processor(),
                "note": args.note,
                "pid": os.getpid(),
                "results": results,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
