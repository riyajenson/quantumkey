"""Enrollment invites: first registration needs a single-use invite (R-02).

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "enrollment_invites",
        sa.Column("invite_id", sa.String(32), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("token_hash", sa.LargeBinary, nullable=False, unique=True),
        sa.Column("expires_at", sa.Float, nullable=False),
        sa.Column("used_at", sa.Float, nullable=True),
        sa.Column("created_at", sa.Float, nullable=False),
    )
    with op.batch_alter_table("challenges") as batch:
        batch.add_column(sa.Column("invite_id", sa.String(32), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("challenges") as batch:
        batch.drop_column("invite_id")
    op.drop_table("enrollment_invites")
