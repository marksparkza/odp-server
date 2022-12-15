"""Add provider timestamp

Revision ID: fd11fd3ad5e1
Revises: 213da8b3a737
Create Date: 2022-12-14 19:52:15.774291

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fd11fd3ad5e1'
down_revision = '213da8b3a737'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - plus server_default ###
    op.add_column('provider', sa.Column('timestamp', sa.TIMESTAMP(timezone=True), nullable=False,
                                        server_default=sa.text('current_timestamp')))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic ###
    op.drop_column('provider', 'timestamp')
    # ### end Alembic commands ###