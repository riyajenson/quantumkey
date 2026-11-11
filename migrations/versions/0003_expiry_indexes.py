"""Index expiry columns so purging expired rows stays cheap (R-10).

Revision ID: 0003
Revises: 0002
"""
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_challenges_expires_at", "challenges", ["expires_at"])
    op.create_index("ix_enrollment_invites_expires_at", "enrollment_invites", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_enrollment_invites_expires_at", table_name="enrollment_invites")
    op.drop_index("ix_challenges_expires_at", table_name="challenges")
