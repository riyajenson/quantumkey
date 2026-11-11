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
from quantumkey.authenticator.vault import DEFAULT_KDF, KdfParams, Vault, VaultError
from quantumkey.protocol.policy import Policy


class SoftwareSigner:
    """Private keys live encrypted in the vault.

    With `unlock_ttl=0` (the default) a key is decrypted for one signing call
    only. With `unlock_ttl > 0` an unlocked key stays in memory for that many
    seconds after the unlock (not after the last use), so repeated signatures
    skip the Argon2id derivation. `lock()` ends every session at once. Policy
    is enforced on every signature either way. A key held in a session is
    exposed to anything that can read this process's memory for that long.
    """

    def __init__(
        self,
        vault_path: str | Path,
        pin: str,
        clock: Callable[[], float] = time.time,
        kdf: KdfParams = DEFAULT_KDF,
        unlock_ttl: float = 0.0,
    ) -> None:
        if unlock_ttl < 0:
            raise ValueError("unlock_ttl must not be negative")
        self.vault = Vault(vault_path, kdf=kdf)
        self.device_id = self.vault.device_id
        self.unlock_ttl = unlock_ttl
        self._pin = pin
        self._clock = clock
        self._core = SigningCore(clock)
        self._sessions: dict[str, float] = {}  # credential id -> session end

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
        now = self._clock()
        if now >= self._sessions.get(credential_id, now):
            self._end(credential_id)
            private_key = self.vault.unlock(self._pin, credential_id)  # may raise VaultError
            self._core.add(public, private_key)
            if self.unlock_ttl > 0:
                self._sessions[credential_id] = now + self.unlock_ttl
        try:
            return self._core.sign(credential_id, request)
        finally:
            if credential_id not in self._sessions:
                self._core.forget(credential_id)

    def lock(self) -> None:
        """End every unlocked session now."""
        for credential_id in list(self._sessions):
            self._end(credential_id)

    def delete_credential(self, credential_id: str) -> None:
        """Delete from the vault (the PIN must open it) and end its session."""
        self.vault.delete(self._pin, credential_id)
        self._end(credential_id)

    def _end(self, credential_id: str) -> None:
        self._sessions.pop(credential_id, None)
        self._core.forget(credential_id)


__all__ = ["SoftwareSigner", "VaultError"]
