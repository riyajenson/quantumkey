"""Draft signing-backend contract and liboqs-backed Phase 2 implementation."""

from __future__ import annotations

from typing import Protocol

import oqs


class SigningBackend(Protocol):
    """Minimum operations needed by the current software-backend experiment."""

    def generate_keypair(self, algorithm: str) -> tuple[bytes, bytes]: ...

    def sign(self, algorithm: str, private_key: bytes, message: bytes) -> bytes: ...

    def verify(
        self, algorithm: str, public_key: bytes, message: bytes, signature: bytes
    ) -> bool: ...


class SoftwareMLDSABackend:
    """Thin adapter over the official liboqs-python Signature API."""

    SUPPORTED = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")

    def generate_keypair(self, algorithm: str) -> tuple[bytes, bytes]:
        self._require_supported(algorithm)
        with oqs.Signature(algorithm) as signer:
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
        return public_key, private_key

    def sign(self, algorithm: str, private_key: bytes, message: bytes) -> bytes:
        self._require_supported(algorithm)
        with oqs.Signature(algorithm, secret_key=private_key) as signer:
            return signer.sign(message)

    def verify(
        self, algorithm: str, public_key: bytes, message: bytes, signature: bytes
    ) -> bool:
        self._require_supported(algorithm)
        with oqs.Signature(algorithm) as verifier:
            return verifier.verify(message, signature, public_key)

    @classmethod
    def _require_supported(cls, algorithm: str) -> None:
        if algorithm not in cls.SUPPORTED:
            raise ValueError(f"unsupported algorithm: {algorithm}")
        if algorithm not in oqs.get_enabled_sig_mechanisms():
            raise RuntimeError(f"algorithm is not enabled in this liboqs build: {algorithm}")
