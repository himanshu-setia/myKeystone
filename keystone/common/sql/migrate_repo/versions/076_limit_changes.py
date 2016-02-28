import migrate
import sqlalchemy as sql
from oslo_log import log

LOG = log.getLogger(__name__)

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    user = sql.Table('user', meta, autoload=True)
    user.c.name.alter(type=sql.String(length=64))

    jio_policy = sql.Table('jio_policy', meta, autoload=True)
    jio_policy.c.name.alter(type=sql.String(length=64)) 
    jio_policy.c.policy_blob.alter(type=sql.String(length=2048))
