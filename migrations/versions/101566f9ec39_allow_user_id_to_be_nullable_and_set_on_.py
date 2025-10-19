"""Allow user_id to be nullable and set ON DELETE SET NULL

Revision ID: 101566f9ec39
Revises: effad42d3deb
Create Date: 2025-09-25 02:19:29.209235

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '101566f9ec39'
down_revision = 'effad42d3deb'
branch_labels = None
depends_on = None


def upgrade():
    # Make user_id nullable and set ON DELETE SET NULL without trying to drop unnamed constraints
    with op.batch_alter_table('deep_scan_request', schema=None) as batch_op:
        batch_op.alter_column('user_id',
               existing_type=sa.INTEGER(),
               nullable=True)
        batch_op.create_foreign_key(
            'fk_deep_scan_user_id', 'user', ['user_id'], ['id'], ondelete='SET NULL'
        )

    with op.batch_alter_table('scan', schema=None) as batch_op:
        batch_op.alter_column('user_id',
               existing_type=sa.INTEGER(),
               nullable=True)
        batch_op.create_foreign_key(
            'fk_scan_user_id', 'user', ['user_id'], ['id'], ondelete='SET NULL'
        )

    with op.batch_alter_table('user_log', schema=None) as batch_op:
        batch_op.alter_column('user_id',
               existing_type=sa.INTEGER(),
               nullable=True)
        batch_op.create_foreign_key(
            'fk_user_log_user_id', 'user', ['user_id'], ['id'], ondelete='SET NULL'
        )


def downgrade():
    with op.batch_alter_table('user_log', schema=None) as batch_op:
        batch_op.drop_constraint('fk_user_log_user_id_user', type_='foreignkey')
        batch_op.alter_column('user_id',
               existing_type=sa.INTEGER(),
               nullable=False)
        batch_op.create_foreign_key('fk_user_log_user_id_user', 'user', ['user_id'], ['id'])

    with op.batch_alter_table('scan', schema=None) as batch_op:
        batch_op.drop_constraint('fk_scan_user_id_user', type_='foreignkey')
        batch_op.alter_column('user_id',
               existing_type=sa.INTEGER(),
               nullable=False)
        batch_op.create_foreign_key('fk_scan_user_id_user', 'user', ['user_id'], ['id'])

    with op.batch_alter_table('deep_scan_request', schema=None) as batch_op:
        batch_op.drop_constraint('fk_deep_scan_request_user_id_user', type_='foreignkey')
        batch_op.alter_column('user_id',
               existing_type=sa.INTEGER(),
               nullable=False)
        batch_op.create_foreign_key('fk_deep_scan_request_user_id_user', 'user', ['user_id'], ['id'])


    # ### end Alembic commands ###
