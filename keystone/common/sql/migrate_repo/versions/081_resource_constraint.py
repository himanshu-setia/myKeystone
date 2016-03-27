import migrate
import sqlalchemy as sql
from migrate.changeset.constraint import UniqueConstraint

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    resource_table = sql.Table('resource', meta, autoload=True)
    cons = UniqueConstraint('name', name='unique_resource_name', table=resource_table)
    cons.create()
