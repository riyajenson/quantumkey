from __future__ import annotations

import base64
import os
import sqlite3
import socket
import subprocess
import sys
import time
from uuid import uuid4
from pathlib import Path

import httpx
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

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
    explicit_test_url = os.environ.get("QK_TEST_DATABASE_URL")
    if explicit_test_url:
        parsed_url = make_url(explicit_test_url)
        if (
            parsed_url.drivername != "postgresql+psycopg"
            or parsed_url.host not in {"localhost", "127.0.0.1", "::1"}
            or not (parsed_url.database or "").startswith("qk_test_")
        ):
            raise ValueError(
                "QK_TEST_DATABASE_URL must target a loopback PostgreSQL database "
                "whose name starts with qk_test_"
            )
        database_url = explicit_test_url
        # Start every run from an empty database, as tests/helpers.database_url
        # does: the parametrized runs register the same credential id.
        engine = create_engine(database_url)
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        engine.dispose()
    else:
        database_url = "sqlite:///" + (tmp_path / "validation.sqlite3").as_posix()
    env = os.environ.copy()
    env["QK_DATABASE_URL"] = database_url
    env.pop("QK_TEST_DATABASE_URL", None)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")

    class RunningApi:
        def __init__(self) -> None:
            self.process: subprocess.Popen[str] | None = None
            self.url = ""
            self.database_dialect = make_url(database_url).get_backend_name()
            self.start()

        def start(self) -> None:
            port = _unused_port()
            self.url = f"http://127.0.0.1:{port}"
            self.process = subprocess.Popen(
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
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    if self.process.poll() is not None:
                        details = self.process.stderr.read()
                        raise RuntimeError(f"validation API exited: {details}")
                    try:
                        response = httpx.get(f"{self.url}/health", timeout=0.25)
                        if response.status_code == 200:
                            return
                    except httpx.HTTPError:
                        time.sleep(0.1)
                raise TimeoutError("validation API did not become healthy")
            except Exception:
                self.stop()
                raise

        def stop(self) -> None:
            if self.process is None:
                return
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            if self.process.stderr:
                self.process.stderr.close()
            self.process = None

        def restart(self) -> None:
            self.stop()
            self.start()

    service = RunningApi()
    try:
        yield service
    finally:
        service.stop()


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_authenticator_registers_unlocks_signs_and_server_verifies(
    api, algorithm: str, tmp_path: Path
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

    credential_id = f"device-{algorithm.lower()}-{uuid4().hex}"
    message = b"QuantumKey phase 2 end-to-end validation"
    signature = backend.sign(algorithm, recovered_private_key, message)

    with httpx.Client(base_url=api.url, timeout=5) as client:
        health = client.get("/health")
        assert health.json() == {
            "status": "ok",
            "database": api.database_dialect,
        }

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

        duplicate_public_key, _ = backend.generate_keypair(algorithm)
        duplicate = client.post(
            "/credentials",
            json={
                "credential_id": credential_id,
                "algorithm": algorithm,
                "public_key": base64.b64encode(duplicate_public_key).decode("ascii"),
            },
        )
        assert duplicate.status_code == 409
        preserved = client.get(f"/credentials/{credential_id}")
        assert preserved.status_code == 200, preserved.text
        assert base64.b64decode(preserved.json()["public_key"]) == public_key

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

    api.restart()
    with httpx.Client(base_url=api.url, timeout=5) as client:
        after_restart = client.get(f"/credentials/{credential_id}")
        assert after_restart.status_code == 200, after_restart.text
        assert base64.b64decode(after_restart.json()["public_key"]) == public_key
        verified_after_restart = client.post(
            "/verify",
            json={
                "credential_id": credential_id,
                "message": base64.b64encode(message).decode("ascii"),
                "signature": base64.b64encode(signature).decode("ascii"),
            },
        )
        assert verified_after_restart.status_code == 200
        assert verified_after_restart.json() == {"valid": True}

    assert private_key not in vault_path.read_bytes()
    assert b"research-pin" not in vault_path.read_bytes()
