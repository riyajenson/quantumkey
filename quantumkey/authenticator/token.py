"""Virtual hardware token: a separate process that owns its keys.

This simulates the *interface* of a hardware authenticator (framed commands
over stdio, no key export, structured-request signing, policy enforcement). It
is NOT tamper resistant: it is a process boundary, and its keys exist only in
that process's memory for its lifetime.

Wire format: 4-byte big-endian length, then a UTF-8 JSON object, max 64 KiB.
Commands: info, create, public, sign. There is deliberately no command that
exports a private key and no command that signs caller-supplied bytes. `info`
returns the token's device id, random per token process.
"""

from __future__ import annotations

import json
import secrets
import struct
import subprocess
import sys
from typing import BinaryIO

from quantumkey import crypto
from quantumkey.authenticator.core import (
    MigrationTarget,
    PublicCredential,
    SignRequest,
    SigningCore,
    SigningRefused,
)
from quantumkey.protocol.message import Operation
from quantumkey.protocol.policy import Policy, PolicyError

MAX_FRAME = 65536
_COMMANDS = {
    "info": {"cmd"},
    "create": {"cmd", "algorithm", "policy", "credential_id"},
    "public": {"cmd", "credential_id"},
    "sign": {"cmd", "credential_id", "operation", "rp_id", "transaction_id", "challenge", "target"},
}


class FrameError(Exception):
    pass


def read_frame(stream: BinaryIO) -> dict | None:
    header = stream.read(4)
    if not header:
        return None
    if len(header) != 4:
        raise FrameError("truncated header")
    (length,) = struct.unpack(">I", header)
    if length > MAX_FRAME:
        raise FrameError("frame too large")
    body = stream.read(length)
    if len(body) != length:
        raise FrameError("truncated frame")
    try:
        message = json.loads(body)
    except (ValueError, RecursionError) as exc:  # RecursionError: deeply nested JSON
        raise FrameError("invalid json") from exc
    if not isinstance(message, dict):
        raise FrameError("frame must be an object")
    return message


def write_frame(stream: BinaryIO, message: dict) -> None:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    stream.write(struct.pack(">I", len(body)) + body)
    stream.flush()


def _public_dict(public: PublicCredential) -> dict:
    return {
        "credential_id": public.credential_id,
        "algorithm": public.algorithm,
        "public_key": crypto.b64e(public.public_key),
        "policy": crypto.b64e(public.policy.canonical_bytes()),
    }


def _text(message: dict, key: str) -> str:
    value = message[key]
    if not isinstance(value, str):
        raise TypeError(f"{key} must be a string")
    return value


def _operation(value: object) -> Operation:
    # bool is an int subclass in Python and JSON true would map to 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("operation must be an integer")
    return Operation(value)


def handle(core: SigningCore, message: dict, device_id: str = "") -> dict:
    command = message.get("cmd")
    allowed = _COMMANDS.get(command) if isinstance(command, str) else None
    if allowed is None:
        return {"ok": False, "error": "unknown command"}
    if not set(message) <= allowed:
        return {"ok": False, "error": "unexpected field"}
    try:
        if command == "info":
            return {"ok": True, "device_id": device_id}
        if command == "create":
            policy = Policy.from_bytes(crypto.b64d(_text(message, "policy")))
            public, _private = core.create(
                _text(message, "algorithm"), policy, _text(message, "credential_id")
            )
            return {"ok": True, **_public_dict(public)}
        if command == "public":
            return {"ok": True, **_public_dict(core.public(_text(message, "credential_id")))}
        target = message.get("target")
        if target is not None and (
            not isinstance(target, dict)
            or set(target) != {"credential_id", "algorithm", "public_key", "policy_hash"}
        ):
            raise TypeError("malformed migration target")
        request = SignRequest(
            operation=_operation(message["operation"]),
            rp_id=_text(message, "rp_id"),
            transaction_id=_text(message, "transaction_id"),
            challenge=crypto.b64d(_text(message, "challenge")),
            target=None
            if target is None
            else MigrationTarget(
                credential_id=_text(target, "credential_id"),
                algorithm=_text(target, "algorithm"),
                public_key=crypto.b64d(_text(target, "public_key")),
                policy_hash=crypto.b64d(_text(target, "policy_hash")),
            ),
        )
        signature = core.sign(_text(message, "credential_id"), request)
        return {"ok": True, "signature": crypto.b64e(signature)}
    except SigningRefused as exc:
        return {"ok": False, "error": str(exc)}
    except (KeyError, TypeError, ValueError, PolicyError, crypto.CryptoError):
        return {"ok": False, "error": "malformed request"}


def serve(stdin: BinaryIO, stdout: BinaryIO) -> None:
    core = SigningCore()
    device_id = "qkd-" + secrets.token_hex(16)
    while True:
        try:
            message = read_frame(stdin)
        except FrameError as exc:
            write_frame(stdout, {"ok": False, "error": str(exc)})
            return  # framing is lost; a real device would reset
        if message is None:
            return
        write_frame(stdout, handle(core, message, device_id))


class VirtualToken:
    """Host-side Signer proxy that talks to the token process."""

    def __init__(self) -> None:
        self._process = subprocess.Popen(
            [sys.executable, "-m", "quantumkey.authenticator.token_entry"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self._device_id: str | None = None

    def __enter__(self) -> "VirtualToken":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._process.poll() is None:
            self._process.stdin.close()
            self._process.wait(timeout=10)
        self._process.stdout.close()

    def _call(self, message: dict) -> dict:
        write_frame(self._process.stdin, message)
        reply = read_frame(self._process.stdout)
        if reply is None:
            raise SigningRefused("token disconnected")
        if not reply.get("ok"):
            raise SigningRefused(reply.get("error", "token error"))
        return reply

    @property
    def device_id(self) -> str:
        if self._device_id is None:
            self._device_id = self._call({"cmd": "info"})["device_id"]
        return self._device_id

    @staticmethod
    def _public(reply: dict) -> PublicCredential:
        return PublicCredential(
            reply["credential_id"],
            reply["algorithm"],
            crypto.b64d(reply["public_key"]),
            Policy.from_bytes(crypto.b64d(reply["policy"])),
        )

    def create_credential(self, algorithm: str, policy: Policy, credential_id: str) -> PublicCredential:
        return self._public(
            self._call(
                {
                    "cmd": "create",
                    "algorithm": algorithm,
                    "policy": crypto.b64e(policy.canonical_bytes()),
                    "credential_id": credential_id,
                }
            )
        )

    def public_credential(self, credential_id: str) -> PublicCredential:
        return self._public(self._call({"cmd": "public", "credential_id": credential_id}))

    def sign(self, credential_id: str, request: SignRequest) -> bytes:
        target = request.target
        reply = self._call(
            {
                "cmd": "sign",
                "credential_id": credential_id,
                "operation": int(request.operation),
                "rp_id": request.rp_id,
                "transaction_id": request.transaction_id,
                "challenge": crypto.b64e(request.challenge),
                "target": None
                if target is None
                else {
                    "credential_id": target.credential_id,
                    "algorithm": target.algorithm,
                    "public_key": crypto.b64e(target.public_key),
                    "policy_hash": crypto.b64e(target.policy_hash),
                },
            }
        )
        return crypto.b64d(reply["signature"])

