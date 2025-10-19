"""Add company_id, is_shared, evidence

Revision ID: df8cce475481
Revises: 101566f9ec39
Create Date: 2025-10-04 21:27:07.774577

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'df8cce475481'
down_revision = '101566f9ec39'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('scan', schema=None) as batch_op:
        batch_op.add_column(sa.Column('company_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('is_shared', sa.Boolean(), server_default=sa.text('0')))
        batch_op.create_foreign_key(
            'fk_scan_company_id',       # ✅ Name the foreign key constraint
            'company',                  # 🔗 Reference table
            ['company_id'],             # 🔑 Local column
            ['id'],                     # 🔑 Remote column
            ondelete='SET NULL'
        )

    with op.batch_alter_table('vulnerability', schema=None) as batch_op:
        batch_op.add_column(sa.Column('evidence', sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table('vulnerability', schema=None) as batch_op:
        batch_op.drop_column('evidence')

    with op.batch_alter_table('scan', schema=None) as batch_op:
        batch_op.drop_constraint('fk_scan_company_id', type_='foreignkey')  # 🔄 Match the name used above
        batch_op.drop_column('is_shared')
        batch_op.drop_column('company_id')
