import migrate
import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker
from migrate.changeset.constraint import ForeignKeyConstraint

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user_table = sql.Table('user', meta, autoload=True)
    user_type_column = sql.Column('type', sql.Enum('regular', 'root', name='type'), nullable=False)
    user_type_column.create(user_table)

    account_table = sql.Table('account', meta, autoload=True)
    # ca : customer account, console: console account, csa: customer service account, isa: iam special account
    account_type_column = sql.Column('type', sql.Enum('ca', 'console', 'csa', 'isa', name='type'), nullable=False)
    account_type_column.create(account_table)

    jio_policy_table = sql.Table('jio_policy', meta, autoload=True)
    account_table = sql.Table('account', meta, autoload=True)
    cons = ForeignKeyConstraint([jio_policy_table.c.account_id],[account_table.c.id])
    cons.create()
