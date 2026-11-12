"""Credential-bound signing policy.

The canonical policy bytes are hashed and the hash is bound into the
registration message, so the server and the signer agree on the policy and it
cannot be swapped after enrollment.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from quantumkey.protocol.message import Operation


# A recovery credential can be enrolled (its proof of possession is a register
# signature), then enroll and revoke other credentials, but never log in or
# migrate. Kept offline, it replaces every lost device (ADR 0009).
RECOVERY_OPS = ("register", "enroll", "revoke")


class PolicyError(ValueError):
    """Raised for malformed policies or policy violations."""


@dataclass(frozen=True)
class Policy:
    rp_id: str
    allowed_ops: tuple[str, ...] = ("register", "login", "migrate", "enroll", "revoke")
    not_after: int | None = None  # unix seconds; None means no expiry
    max_signs_per_minute: int = 30

    def __post_init__(self) -> None:
        valid = {op.name.lower() for op in Operation}
        # Reject type confusion explicitly (JSON true == 1, 1.5, non-strings...).
        if not isinstance(self.rp_id, str):
            raise PolicyError("rp_id must be a string")
        if not isinstance(self.allowed_ops, tuple) or not all(
            isinstance(op, str) for op in self.allowed_ops
        ):
            raise PolicyError("allowed_ops must be strings")
        if self.not_after is not None and (
            isinstance(self.not_after, bool) or not isinstance(self.not_after, int)
        ):
            raise PolicyError("not_after must be an integer or null")
        if isinstance(self.max_signs_per_minute, bool) or not isinstance(
            self.max_signs_per_minute, int
        ):
            raise PolicyError("max_signs_per_minute must be an integer")
        if not self.rp_id:
            raise PolicyError("rp_id is required")
        if not self.allowed_ops or not set(self.allowed_ops) <= valid:
            raise PolicyError(f"allowed_ops must be a non-empty subset of {sorted(valid)}")
        if self.max_signs_per_minute < 1:
            raise PolicyError("max_signs_per_minute must be positive")

    def canonical_bytes(self) -> bytes:
        document = {
            "allowed_ops": sorted(set(self.allowed_ops)),
            "max_signs_per_minute": self.max_signs_per_minute,
            "not_after": self.not_after,
            "rp_id": self.rp_id,
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> bytes:
        return hashlib.sha256(self.canonical_bytes()).digest()

    @classmethod
    def from_bytes(cls, data: bytes) -> "Policy":
        try:
            document = json.loads(data)
            if not isinstance(document["allowed_ops"], list):
                raise PolicyError("allowed_ops must be a list")
            policy = cls(
                rp_id=document["rp_id"],
                allowed_ops=tuple(document["allowed_ops"]),
                not_after=document["not_after"],
                max_signs_per_minute=document["max_signs_per_minute"],
            )
        # Python's json raises RecursionError, not ValueError, on deeply nested input.
        except (ValueError, KeyError, TypeError, RecursionError) as exc:
            raise PolicyError("malformed policy") from exc
        if policy.canonical_bytes() != data:
            raise PolicyError("policy is not in canonical form")
        return policy

    def check(
        self, operation: Operation, rp_id: str, now: float, signs_in_last_minute: int
    ) -> None:
        """Raise PolicyError unless this request is allowed."""
        if rp_id != self.rp_id:
            raise PolicyError("relying party does not match policy")
        if operation.name.lower() not in self.allowed_ops:
            raise PolicyError(f"operation {operation.name.lower()} not allowed")
        if self.not_after is not None and now > self.not_after:
            raise PolicyError("policy has expired")
        if signs_in_last_minute >= self.max_signs_per_minute:
            raise PolicyError("rate limit exceeded")
