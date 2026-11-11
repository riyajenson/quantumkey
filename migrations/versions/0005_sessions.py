"""Server-side login sessions: only the token's SHA-256 is stored (T-15).

Revision ID: 0005
Revises: 0004
"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("token_hash", sa.LargeBinary, primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("credential_id", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.Float, nullable=False),
        sa.Column("created_at", sa.Float, nullable=False),
    )
    op.create_index("ix_sessions_credential_id", "sessions", ["credential_id"])
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_sessions_expires_at", table_name="sessions")
    op.drop_index("ix_sessions_credential_id", table_name="sessions")
    op.drop_table("sessions")
