"""Add recipient_id to Notification

Revision ID: 8deb4761c668
Revises: bf78786dfa8b
Create Date: 2025-10-15 14:04:28.932201
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8deb4761c668'
down_revision = 'bf78786dfa8b'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('notification', schema=None) as batch_op:
        batch_op.add_column(sa.Column('recipient_id', sa.Integer(), nullable=False))
        # 🟩 give the foreign key constraint a name
        batch_op.create_foreign_key(
            'fk_notification_recipient',  # ✅ name required for SQLite
            'user',                       # target table
            ['recipient_id'],              # local column
            ['id']                         # remote column
        )


def downgrade():
    with op.batch_alter_table('notification', schema=None) as batch_op:
        batch_op.drop_constraint('fk_notification_recipient', type_='foreignkey')
        batch_op.drop_column('recipient_id')
