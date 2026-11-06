"""Canonical signed-message encoding (QuantumKey protocol v1).

Layout: DOMAIN | operation (1 byte) | 7 fields, each a 4-byte big-endian
length followed by the bytes. Parsing is strict: wrong domain, unknown
operation, truncated or trailing bytes, and oversized fields are rejected.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, fields
from enum import IntEnum

DOMAIN = b"QuantumKey/v1\x00"
MAX_FIELD_BYTES = 8192


class Operation(IntEnum):
    REGISTER = 1
    LOGIN = 2
    MIGRATE = 3


class MessageError(ValueError):
    """Raised when a signed message cannot be encoded or parsed."""


@dataclass(frozen=True)
class SignedMessage:
    operation: Operation
    rp_id: bytes
    transaction_id: bytes
    challenge: bytes
    credential_id: bytes
    algorithm: bytes
    policy_hash: bytes
    extra: bytes = b""

    def encode(self) -> bytes:
        parts = [DOMAIN, bytes([int(self.operation)])]
        for name in _FIELD_NAMES:
            value = getattr(self, name)
            if not isinstance(value, bytes):
                raise MessageError(f"{name} must be bytes")
            if len(value) > MAX_FIELD_BYTES:
                raise MessageError(f"{name} is too long")
            parts.append(struct.pack(">I", len(value)))
            parts.append(value)
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "SignedMessage":
        if not data.startswith(DOMAIN):
            raise MessageError("wrong domain tag")
        pos = len(DOMAIN)
        if len(data) <= pos:
            raise MessageError("truncated message")
        try:
            operation = Operation(data[pos])
        except ValueError as exc:
            raise MessageError("unknown operation") from exc
        pos += 1
        values: dict[str, bytes] = {}
        for name in _FIELD_NAMES:
            if pos + 4 > len(data):
                raise MessageError("truncated message")
            (length,) = struct.unpack(">I", data[pos : pos + 4])
            pos += 4
            if length > MAX_FIELD_BYTES:
                raise MessageError(f"{name} is too long")
            if pos + length > len(data):
                raise MessageError("truncated message")
            values[name] = data[pos : pos + length]
            pos += length
        if pos != len(data):
            raise MessageError("trailing bytes")
        return cls(operation=operation, **values)


_FIELD_NAMES = tuple(f.name for f in fields(SignedMessage) if f.name != "operation")
