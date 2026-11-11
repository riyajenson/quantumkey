"""Operator commands for the relying party. They act on the database directly;
there is no HTTP admin API.

    python -m quantumkey.server.admin invite alice [--ttl-hours 24]
    python -m quantumkey.server.admin purge

Prints the invite token once. Only its SHA-256 is stored, so a lost token
cannot be recovered; issue a new one. Hand it to the user out of band.
`purge` deletes expired challenges, expired or used invites and expired
sessions; the server also
does this by itself at most once a minute.
"""

from __future__ import annotations

import argparse
import os
import sys

from quantumkey.server.service import INVITE_TTL, ProtocolError, RelyingParty


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="quantumkey-admin")
    parser.add_argument(
        "--database-url",
        default=os.environ.get("QK_DATABASE_URL", "sqlite:///quantumkey.sqlite3"),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    invite = commands.add_parser("invite", help="issue a single-use registration invite")
    invite.add_argument("username")
    invite.add_argument("--ttl-hours", type=float, default=INVITE_TTL / 3600)
    commands.add_parser("purge", help="delete expired challenges, invites and sessions")

    args = parser.parse_args(argv)
    rp = RelyingParty(args.database_url, rp_id="quantumkey.local")
    try:
        if args.command == "purge":
            challenges, invites, sessions = rp.purge_expired()
            print(f"purged {challenges} challenges, {invites} invites, {sessions} sessions")
        else:
            print(rp.issue_invite(args.username, ttl=args.ttl_hours * 3600))
    except ProtocolError as exc:
        print(f"error: {exc.code}", file=sys.stderr)
        return 1
    finally:
        rp.engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
