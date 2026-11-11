"""Command-line authenticator.

    python -m quantumkey.authenticator.cli --vault vault.sqlite3 register alice --invite <token>
    python -m quantumkey.authenticator.cli --vault vault.sqlite3 login alice
    python -m quantumkey.authenticator.cli --vault vault.sqlite3 list
    python -m quantumkey.authenticator.cli --vault vault.sqlite3 migrate alice <old-credential-id>
    python -m quantumkey.authenticator.cli --vault vault.sqlite3 delete <credential-id>
    python -m quantumkey.authenticator.cli --vault vault.sqlite3 change-pin [--time-cost 3 --memory-kib 65536]

The invite comes from the server operator (`python -m quantumkey.server.admin invite alice`).
The PIN comes from the QK_PIN environment variable or an interactive prompt,
and for change-pin the new PIN from QK_NEW_PIN or a prompt (asked twice).
`migrate` creates the new credential inside a virtual token process, so it
only demonstrates the flow within a single command (the token does not persist).
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

import httpx

from quantumkey import crypto
from quantumkey.authenticator.client import AuthClient, ServerRejected
from quantumkey.authenticator.core import SigningRefused
from quantumkey.authenticator.software import SoftwareSigner
from quantumkey.authenticator.token import VirtualToken
from quantumkey.authenticator.vault import DEFAULT_KDF, KdfParams, VaultError


def _pin() -> str:
    return os.environ.get("QK_PIN") or getpass.getpass("Vault PIN: ")


def _new_pin() -> str:
    if os.environ.get("QK_NEW_PIN"):
        return os.environ["QK_NEW_PIN"]
    first = getpass.getpass("New PIN: ")
    if first != getpass.getpass("Repeat new PIN: "):
        raise VaultError("the new PINs do not match")
    return first


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="quantumkey")
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    parser.add_argument("--rp-id", default="quantumkey.local")
    parser.add_argument("--vault", default="quantumkey-vault.sqlite3")
    commands = parser.add_subparsers(dest="command", required=True)

    register = commands.add_parser("register")
    register.add_argument("username")
    register.add_argument("--invite", required=True, help="one-time invite from the server operator")
    register.add_argument("--algorithm", choices=crypto.ALGORITHMS, default=crypto.DEFAULT_ALGORITHM)
    login = commands.add_parser("login")
    login.add_argument("username")
    login.add_argument("--credential-id")
    commands.add_parser("list")
    migrate = commands.add_parser("migrate")
    migrate.add_argument("username")
    migrate.add_argument("credential_id")
    delete = commands.add_parser("delete", help="delete a credential from this vault")
    delete.add_argument("credential_id")
    change_pin = commands.add_parser(
        "change-pin",
        help="re-encrypt every credential under a new PIN and Argon2id parameters "
        "(see python -m quantumkey.authenticator.calibrate)",
    )
    change_pin.add_argument("--time-cost", type=int, default=DEFAULT_KDF.time_cost)
    change_pin.add_argument("--memory-kib", type=int, default=DEFAULT_KDF.memory_kib)
    change_pin.add_argument("--parallelism", type=int, default=DEFAULT_KDF.parallelism)

    args = parser.parse_args(argv)
    try:
        pin = _pin()
        signer = SoftwareSigner(args.vault, pin)
        if args.command == "list":
            for item in signer.vault.list_credentials():
                print(f"{item.credential_id}\t{item.algorithm}")
            return 0
        if args.command == "delete":
            try:
                signer.delete_credential(args.credential_id)
            except KeyError:
                print(f"error: unknown credential: {args.credential_id}", file=sys.stderr)
                return 1
            print(f"deleted {args.credential_id} from the vault")
            print("note: it is still active on the server, which has no revoke endpoint yet")
            return 0
        if args.command == "change-pin":
            kdf = KdfParams(args.time_cost, args.memory_kib, args.parallelism)
            kdf.check()
            count = signer.vault.change_pin(pin, _new_pin(), kdf=kdf)
            print(f"PIN changed for {count} credential(s)")
            return 0
        with httpx.Client(base_url=args.server, timeout=10) as http:
            client = AuthClient(http, args.rp_id)
            if args.command == "register":
                print("registered", client.register(args.username, signer, args.algorithm, invite=args.invite))
            elif args.command == "login":
                client.login(args.username, signer, args.credential_id)
                print("login ok")
            elif args.command == "migrate":
                with VirtualToken() as token:
                    new_id = client.migrate(
                        args.username, args.credential_id, signer, token
                    )
                    print("migrated to virtual-token credential", new_id)
                    client.login(args.username, token)
                    print("login with migrated credential ok")
    except (ServerRejected, SigningRefused, VaultError, httpx.HTTPError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
