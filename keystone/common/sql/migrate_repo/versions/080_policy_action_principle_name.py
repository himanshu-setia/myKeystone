import sqlalchemy as sql
from sqlalchemy.orm import sessionmaker
from migrate.changeset.constraint import ForeignKeyConstraint
from oslo_log import log

LOG = log.getLogger(__name__)

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    policy_action_principle_table = sql.Table('policy_action_principle', meta, autoload=True)
    policy_action_principle_table.c.principle_id.alter(name='principle_name')
