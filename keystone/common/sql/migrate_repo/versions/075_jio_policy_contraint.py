import migrate
import sqlalchemy as sql
from migrate.changeset.constraint import UniqueConstraint

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    jio_policy_table = sql.Table('jio_policy', meta, autoload=True)
    cons = UniqueConstraint('name', 'account_id','type', name='unique_name_accountid_type', table=jio_policy_table)
    cons.create()

