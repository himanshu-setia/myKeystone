import migrate
import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker
from migrate.changeset.constraint import ForeignKeyConstraint

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    account_table = sql.Table('account', meta, autoload=True)
    # ca : customer account, console: console account, csa: customer service account, isa: iam special account
    account_type_column = sql.Column('billing_type', sql.Enum('internal', 'external', name='billing_type'), nullable=False)
    account_type_column.create(account_table)
