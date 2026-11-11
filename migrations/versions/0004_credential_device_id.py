"""Record the (self-reported) device a credential was created on.

Revision ID: 0004
Revises: 0003
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("credentials") as batch:
        batch.add_column(sa.Column("device_id", sa.String(64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("credentials") as batch:
        batch.drop_column("device_id")
