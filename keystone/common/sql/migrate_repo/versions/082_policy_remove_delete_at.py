import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker
from migrate.changeset.constraint import ForeignKeyConstraint
from oslo_log import log

LOG = log.getLogger(__name__)

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    jio_policy = sql.Table('jio_policy', meta, autoload=True)
    jio_policy.c.deleted_at.drop()
