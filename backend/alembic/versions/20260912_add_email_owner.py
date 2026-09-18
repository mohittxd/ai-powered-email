"""Associate ingested emails with their authenticated owner."""

from alembic import op
import sqlalchemy as sa

revision = "20260912_add_email_owner"
down_revision = "177ce842bf95"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("emails", sa.Column("owner_id", sa.String(length=36), nullable=True))
    op.create_index("ix_emails_owner_id", "emails", ["owner_id"])
    op.create_foreign_key("fk_emails_owner_id_users", "emails", "users", ["owner_id"], ["id"])


def downgrade() -> None:
    op.drop_constraint("fk_emails_owner_id_users", "emails", type_="foreignkey")
    op.drop_index("ix_emails_owner_id", table_name="emails")
    op.drop_column("emails", "owner_id")
