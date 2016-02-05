from oslo_log import log
import sqlalchemy as sql
from keystone.common import sql as key_sql

LOG = log.getLogger(__name__)

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    jio_policy = sql.Table('jio_policy', meta, autoload=True)
    jio_policy.c.project_id.alter(name='account_id')

def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    jio_policy = sql.Table('jio_policy', meta, autoload=True)
    jio_policy.c.account_id.alter(name='project_id')
