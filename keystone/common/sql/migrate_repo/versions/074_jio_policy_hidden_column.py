import migrate
import sqlalchemy as sql
from oslo_log import log

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    jio_policy_table = sql.Table('jio_policy', meta, autoload=True)
    jio_policy_hidden_column = sql.Column('hidden', sql.Boolean, default=False, nullable=True)
    jio_policy_hidden_column.create(jio_policy_table)
