"""Initial relying-party schema: users, credentials, challenges.

Revision ID: 0001
Revises:
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("username", sa.String(64), primary_key=True),
        sa.Column("created_at", sa.Float, nullable=False),
    )
    op.create_table(
        "credentials",
        sa.Column("credential_id", sa.String(128), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("algorithm", sa.String(32), nullable=False),
        sa.Column("public_key", sa.LargeBinary, nullable=False),
        sa.Column("policy", sa.LargeBinary, nullable=False),
        sa.Column("policy_hash", sa.LargeBinary, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("replaced_by", sa.String(128), nullable=True),
        sa.Column("created_at", sa.Float, nullable=False),
    )
    op.create_index("ix_credentials_username", "credentials", ["username"])
    op.create_table(
        "challenges",
        sa.Column("transaction_id", sa.String(64), primary_key=True),
        sa.Column("purpose", sa.String(16), nullable=False),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("credential_id", sa.String(128), nullable=True),
        sa.Column("algorithm", sa.String(32), nullable=False),
        sa.Column("challenge", sa.LargeBinary, nullable=False),
        sa.Column("expires_at", sa.Float, nullable=False),
        sa.Column("used_at", sa.Float, nullable=True),
        sa.Column("created_at", sa.Float, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("challenges")
    op.drop_index("ix_credentials_username", table_name="credentials")
    op.drop_table("credentials")
    op.drop_table("users")
