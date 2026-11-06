"""Software signer: vault-backed storage in front of the signing core."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from quantumkey.authenticator.core import (
    PublicCredential,
    SignRequest,
    SigningCore,
    SigningRefused,
)
from quantumkey.authenticator.vault import Vault, VaultError
from quantumkey.protocol.policy import Policy


class SoftwareSigner:
    """Private keys live encrypted in the vault; they are decrypted only for
    the duration of one signing call."""

    def __init__(
        self,
        vault_path: str | Path,
        pin: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.vault = Vault(vault_path)
        self._pin = pin
        self._core = SigningCore(clock)

    def create_credential(
        self, algorithm: str, policy: Policy, credential_id: str
    ) -> PublicCredential:
        public, private_key = self._core.create(algorithm, policy, credential_id)
        try:
            self.vault.put(
                self._pin, credential_id, algorithm, public.public_key, policy, private_key
            )
        finally:
            self._core.forget(credential_id)
        return public

    def public_credential(self, credential_id: str) -> PublicCredential:
        try:
            stored = self.vault.get_public(credential_id)
        except KeyError as exc:
            raise SigningRefused("unknown credential") from exc
        return PublicCredential(
            stored.credential_id, stored.algorithm, stored.public_key, stored.policy
        )

    def sign(self, credential_id: str, request: SignRequest) -> bytes:
        public = self.public_credential(credential_id)
        private_key = self.vault.unlock(self._pin, credential_id)  # may raise VaultError
        self._core.add(public, private_key)
        try:
            return self._core.sign(credential_id, request)
        finally:
            self._core.forget(credential_id)


__all__ = ["SoftwareSigner", "VaultError"]
