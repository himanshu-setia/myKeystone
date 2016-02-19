import migrate
import sqlalchemy as sql
from migrate.changeset.constraint import UniqueConstraint
from oslo_log import log

LOG = log.getLogger(__name__)

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    policy_action_prin = sql.Table('policy_action_principle', meta, autoload=True)
    policy_action_prin.c.principle_type.alter(type=sql.Enum('User', 'Group', '*', name='type'))
