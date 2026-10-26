from __future__ import annotations

import base64
import os
import sqlite3
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from phase2.signing_backend import SoftwareMLDSABackend
from phase2.vault import CredentialVault, SQLiteCredentialVault, VaultUnlockError


ROOT = Path(__file__).resolve().parents[3]
ALGORITHMS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")


def _unused_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@pytest.fixture
def api(tmp_path: Path):
    port = _unused_port()
    env = os.environ.copy()
    env["QK_VALIDATION_DATABASE"] = str(tmp_path / "validation.sqlite3")
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "phase2.validation_service:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "error",
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"validation API exited: {process.stderr.read()}")
            try:
                response = httpx.get(f"{base_url}/health", timeout=0.25)
                if response.status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.1)
        else:
            raise TimeoutError("validation API did not become healthy")
        yield base_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if process.stderr:
            process.stderr.close()


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_authenticator_registers_unlocks_signs_and_server_verifies(
    api: str, algorithm: str, tmp_path: Path
):
    backend = SoftwareMLDSABackend()
    public_key, private_key = backend.generate_keypair(algorithm)

    vault_path = tmp_path / "authenticator.sqlite3"
    vault = SQLiteCredentialVault(vault_path)
    vault.put("credential-1", algorithm, "research-pin", private_key)
    vault = SQLiteCredentialVault(vault_path)
    recovered_private_key = vault.get("credential-1", "research-pin")
    assert recovered_private_key == private_key
    with pytest.raises(VaultUnlockError):
        vault.get("credential-1", "wrong-pin")
    with sqlite3.connect(vault_path) as connection:
        connection.execute(
            "UPDATE credentials SET algorithm = ? WHERE credential_id = ?",
            ("tampered-algorithm", "credential-1"),
        )
    with pytest.raises(VaultUnlockError):
        vault.get("credential-1", "research-pin")

    credential_id = f"device-{algorithm.lower()}"
    message = b"QuantumKey phase 2 end-to-end validation"
    signature = backend.sign(algorithm, recovered_private_key, message)

    with httpx.Client(base_url=api, timeout=5) as client:
        registered = client.post(
            "/credentials",
            json={
                "credential_id": credential_id,
                "algorithm": algorithm,
                "public_key": base64.b64encode(public_key).decode("ascii"),
            },
        )
        assert registered.status_code == 201, registered.text

        persisted = client.get(f"/credentials/{credential_id}")
        assert persisted.status_code == 200, persisted.text
        assert base64.b64decode(persisted.json()["public_key"]) == public_key

        accepted = client.post(
            "/verify",
            json={
                "credential_id": credential_id,
                "message": base64.b64encode(message).decode("ascii"),
                "signature": base64.b64encode(signature).decode("ascii"),
            },
        )
        assert accepted.status_code == 200, accepted.text
        assert accepted.json() == {"valid": True}
        assert base64.b64encode(private_key).decode("ascii") not in accepted.text

        rejected = client.post(
            "/verify",
            json={
                "credential_id": credential_id,
                "message": base64.b64encode(message + b" altered").decode("ascii"),
                "signature": base64.b64encode(signature).decode("ascii"),
            },
        )
        assert rejected.status_code == 200, rejected.text
        assert rejected.json() == {"valid": False}

    assert private_key not in vault_path.read_bytes()
    assert b"research-pin" not in vault_path.read_bytes()
