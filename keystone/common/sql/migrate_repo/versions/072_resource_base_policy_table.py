import migrate
import sqlalchemy as sql
from migrate.changeset.constraint import UniqueConstraint
from oslo_log import log

LOG = log.getLogger(__name__)
  
def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    jio_policy = sql.Table('jio_policy', meta, autoload=True)
    jio_policy_column = sql.Column('type', sql.Enum('UserBased', 'ResourceBased', name='type'), nullable=False)
    jio_policy_column.create(jio_policy)

    action = sql.Table('action', meta, autoload=True)
    resource = sql.Table('resource', meta, autoload=True)
      
    policy_action_principle = sql.Table(
        'policy_action_principle', meta,
        sql.Column('policy_id', sql.String(length=64), nullable=False),
        sql.Column('action_id', sql.String(length=64), nullable=False),
        sql.Column('principle_id', sql.String(length=64), nullable=False),
        sql.Column('principle_type', sql.Enum('User','Group', name='type'), nullable=False),
        sql.Column('principle_acc_id',sql.String(length=64), nullable=False),  
        sql.Column('effect', sql.Boolean, default=False, nullable=False),
        sql.PrimaryKeyConstraint('action_id', 'principle_id', 'policy_id'),
        sql.ForeignKeyConstraint(
            ['policy_id'], ['jio_policy.id'],
            name='fk_policy_action_principle_policy_id'
        ),
        sql.ForeignKeyConstraint(
            ['action_id'], ['action.id'],
            name='fk_policy_action_principle_mapping_action_id'
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    policy_resource_mapping = sql.Table(
        'policy_resource_mapping', meta,
        sql.Column('resource_id', sql.String(64), nullable=False),
        sql.Column('policy_id', sql.String(64), nullable=False),
        sql.PrimaryKeyConstraint('policy_id', 'resource_id'),
        sql.ForeignKeyConstraint(
            ['policy_id'], ['jio_policy.id'],
            name='fk_policy_resource_mapping_policy_id'
        ),
        sql.ForeignKeyConstraint(
            ['resource_id'], ['resource.id'],
            name='fk_policy_resource_mapping_resource_id'
        ),
        mysql_engine='InnoDB',
        mysql_charset='utf8')
 
    tables = [policy_action_principle, policy_resource_mapping]

    for table in tables:
        try:
            table.create()
        except Exception:
            LOG.exception('Exception while creating table: %r', table)
            raise
