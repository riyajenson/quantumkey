"""Command-line authenticator.

    python -m quantumkey.authenticator.cli --vault vault.sqlite3 register alice --invite <token>
    python -m quantumkey.authenticator.cli --vault vault.sqlite3 login alice
    python -m quantumkey.authenticator.cli --vault vault.sqlite3 list
    python -m quantumkey.authenticator.cli --vault vault.sqlite3 migrate alice <old-credential-id>
    python -m quantumkey.authenticator.cli --vault vault.sqlite3 delete <credential-id>
    python -m quantumkey.authenticator.cli --vault vault.sqlite3 enroll alice <credential-id> --new-vault phone.sqlite3
    python -m quantumkey.authenticator.cli --vault phone.sqlite3 revoke alice <lost-id> --with <credential-id>
    python -m quantumkey.authenticator.cli --vault phone.sqlite3 devices alice
    python -m quantumkey.authenticator.cli --vault vault.sqlite3 change-pin [--time-cost 3 --memory-kib 65536]

The invite comes from the server operator (`python -m quantumkey.server.admin invite alice`).
The PIN comes from the QK_PIN environment variable or an interactive prompt,
and for change-pin and the vault created by enroll the new PIN from
QK_NEW_PIN or a prompt (asked twice). `enroll` adds a credential in another
vault, authorized by one in this vault; `revoke` revokes any credential of the
account, authorized by one in this vault (ADR 0009).
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
from quantumkey.protocol.policy import RECOVERY_OPS, Policy


def _pin() -> str:
    return os.environ.get("QK_PIN") or getpass.getpass("Vault PIN: ")


def _new_pin() -> str:
    if os.environ.get("QK_NEW_PIN"):
        return os.environ["QK_NEW_PIN"]
    first = getpass.getpass("New PIN: ")
    if first != getpass.getpass("Repeat new PIN: "):
        raise VaultError("the new PINs do not match")
    return first


def _own_credential(args: argparse.Namespace, signer: SoftwareSigner) -> str | None:
    """The credential to sign in with: the one named, else this vault's only
    credential (on an enrolled device the account's oldest credential may live
    elsewhere), else none and the server chooses."""
    if args.credential_id:
        return args.credential_id
    held = signer.vault.list_credentials()
    return held[0].credential_id if len(held) == 1 else None


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
    enroll = commands.add_parser(
        "enroll", help="add a credential in another vault, authorized by one in this vault"
    )
    enroll.add_argument("username")
    enroll.add_argument("credential_id", help="the authorizing credential in this vault")
    enroll.add_argument("--new-vault", required=True, help="vault for the new credential")
    enroll.add_argument("--algorithm", choices=crypto.ALGORITHMS, default=crypto.DEFAULT_ALGORITHM)
    enroll.add_argument(
        "--recovery", action="store_true",
        help="a recovery credential: may enroll and revoke, never log in; keep it offline",
    )
    revoke = commands.add_parser(
        "revoke", help="revoke a credential of the account, authorized by one in this vault"
    )
    revoke.add_argument("username")
    revoke.add_argument("target_id", help="the credential to revoke")
    revoke.add_argument("--with", dest="authorizer_id", required=True,
                        help="the authorizing credential in this vault")
    devices = commands.add_parser("devices", help="list the account's credentials")
    devices.add_argument("username")
    devices.add_argument("--credential-id", help="credential in this vault to sign in with")
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
            print("note: it is still active on the server; revoke it there with `revoke`")
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
                client.login(args.username, signer, _own_credential(args, signer))
                print("login ok")
            elif args.command == "devices":
                token = client.login(args.username, signer, _own_credential(args, signer))
                try:
                    held = {c.credential_id for c in signer.vault.list_credentials()}
                    print("credential_id\tstatus\talgorithm\tdevice_id\tallowed_ops")
                    for c in client.credentials(token):
                        mark = "\t(this vault)" if c["credential_id"] in held else ""
                        print(
                            f"{c['credential_id']}\t{c['status']}\t{c['algorithm']}\t"
                            f"{c['device_id'] or '-'}\t{','.join(c['allowed_ops'])}{mark}"
                        )
                finally:
                    client.logout(token)
            elif args.command == "enroll":
                new_signer = SoftwareSigner(args.new_vault, _new_pin())
                policy = (
                    Policy(rp_id=args.rp_id, allowed_ops=RECOVERY_OPS) if args.recovery else None
                )
                new_id = client.enroll(
                    args.username, args.credential_id, signer, new_signer, args.algorithm, policy
                )
                kind = " (recovery credential: keep this vault offline)" if args.recovery else ""
                print(f"enrolled {new_id} in {args.new_vault}{kind}")
            elif args.command == "revoke":
                client.revoke(args.username, args.authorizer_id, signer, args.target_id)
                print(f"revoked {args.target_id}")
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
