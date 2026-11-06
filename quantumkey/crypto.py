"""ML-DSA operations through liboqs, plus encoding helpers.

QuantumKey never implements ML-DSA itself; every call goes to liboqs.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import sys

# liboqs-python prints a banner to stdout on import, which would corrupt
# JSON output (bench) and framed protocols (token). Send it to stderr.
with contextlib.redirect_stdout(sys.stderr):
    import oqs

ALGORITHMS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
DEFAULT_ALGORITHM = "ML-DSA-65"

# FIPS 204 sizes in bytes: (public key, signature).
SIZES = {
    "ML-DSA-44": (1312, 2420),
    "ML-DSA-65": (1952, 3309),
    "ML-DSA-87": (2592, 4627),
}


class CryptoError(ValueError):
    """Raised for unsupported algorithms or malformed key material."""


def require_algorithm(algorithm: str) -> None:
    if algorithm not in ALGORITHMS:
        raise CryptoError(f"unsupported algorithm: {algorithm}")


def generate_keypair(algorithm: str) -> tuple[bytes, bytes]:
    """Return (public_key, private_key)."""
    require_algorithm(algorithm)
    with oqs.Signature(algorithm) as signer:
        public_key = signer.generate_keypair()
        return public_key, signer.export_secret_key()


def sign(algorithm: str, private_key: bytes, message: bytes) -> bytes:
    require_algorithm(algorithm)
    with oqs.Signature(algorithm, secret_key=private_key) as signer:
        return signer.sign(message)


def verify(algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return False (never raise) for any malformed or invalid input."""
    try:
        require_algorithm(algorithm)
        public_size, signature_size = SIZES[algorithm]
        if len(public_key) != public_size or len(signature) != signature_size:
            return False
        with oqs.Signature(algorithm) as verifier:
            return bool(verifier.verify(message, signature, public_key))
    except (CryptoError, RuntimeError, ValueError):
        return False


def b64e(data: bytes) -> str:
    """base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    """Strict base64url-without-padding decoder; rejects non-canonical input."""
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise CryptoError("invalid base64url") from exc
    if b64e(data) != text:
        raise CryptoError("non-canonical base64url")
    return data
