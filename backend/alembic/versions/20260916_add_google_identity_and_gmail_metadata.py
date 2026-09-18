"""Add Google identity fields and Gmail synchronization metadata.

This migration is additive and preserves existing users and forensic records.
"""

from alembic import op
import sqlalchemy as sa


revision = "20260916_google_identity_gmail_metadata"
down_revision = "20260912_add_email_owner"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "gmail_connections",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("google_email", sa.String(length=255), nullable=True),
        sa.Column("access_token", sa.Text(), nullable=False),
        sa.Column("refresh_token", sa.Text(), nullable=True),
        sa.Column("token_expiry", sa.DateTime(), nullable=True),
        sa.Column("scopes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("last_sync_at", sa.DateTime(), nullable=True),
        sa.Column("last_sync_stats", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id"),
    )

    op.add_column("users", sa.Column("google_id", sa.String(length=255), nullable=True))
    op.add_column("users", sa.Column("profile_picture", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("users", sa.Column("last_login", sa.DateTime(), nullable=True))
    op.create_index("ix_users_google_id", "users", ["google_id"], unique=True)

    op.add_column("emails", sa.Column("gmail_message_id", sa.String(length=255), nullable=True))
    op.add_column("emails", sa.Column("gmail_thread_id", sa.String(length=255), nullable=True))
    op.add_column("emails", sa.Column("gmail_labels", sa.JSON(), nullable=True))
    op.create_index("ix_emails_gmail_message_id", "emails", ["gmail_message_id"])
    op.create_index("ix_emails_gmail_thread_id", "emails", ["gmail_thread_id"])

def downgrade() -> None:
    op.drop_table("gmail_connections")
    op.drop_index("ix_emails_gmail_thread_id", table_name="emails")
    op.drop_index("ix_emails_gmail_message_id", table_name="emails")
    op.drop_column("emails", "gmail_labels")
    op.drop_column("emails", "gmail_thread_id")
    op.drop_column("emails", "gmail_message_id")
    op.drop_index("ix_users_google_id", table_name="users")
    op.drop_column("users", "last_login")
    op.drop_column("users", "is_active")
    op.drop_column("users", "profile_picture")
    op.drop_column("users", "google_id")
