import migrate
import sqlalchemy as sql
from migrate.changeset.constraint import UniqueConstraint

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    resource_type_table = sql.Table('resource_type', meta, autoload=True)    
    cons = UniqueConstraint('name', 'service_type', name='unique_name_service_name', table=resource_type_table)
    cons.create()
