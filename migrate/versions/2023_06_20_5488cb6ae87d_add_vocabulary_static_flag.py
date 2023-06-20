"""Add vocabulary static flag

Revision ID: 5488cb6ae87d
Revises: 2a11221f8547
Create Date: 2023-06-20 13:38:10.272867

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5488cb6ae87d'
down_revision = '2a11221f8547'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic ###
    op.add_column('vocabulary', sa.Column('static', sa.Boolean(), server_default='false', nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic ###
    op.drop_column('vocabulary', 'static')
    # ### end Alembic commands ###
