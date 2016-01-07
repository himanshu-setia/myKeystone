from oslo_log import log
import sqlalchemy as sql
from keystone.common import sql as key_sql


LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    # create indices for foreign key constraints
    service = sql.Table('service', meta, autoload=True)
    sql.Index('ix_type', service.c.type).create(migrate_engine)

    action = sql.Table(
            'action', meta,
            sql.Column('id', sql.String(length=64), primary_key=True),
            sql.Column('action_name', sql.String(length=255), nullable=False),
            sql.Column('service_type', sql.String(length=255), nullable=False),
            sql.UniqueConstraint('action_name', name='ixu_action_name'),
            sql.ForeignKeyConstraint(
                ['service_type'], ['service.type'],
                name='fk_action_service_type'
            ),
            mysql_engine='InnoDB',
            mysql_charset='utf8')
    resource_type = sql.Table(
            'resource_type', meta,
            sql.Column('id', sql.String(length=64), primary_key=True),
            sql.Column('name', sql.String(length=255), nullable=False),
            sql.Column('service_type', sql.String(length=255), nullable=False),
            sql.ForeignKeyConstraint(
                ['service_type'], ['service.type'],
                name='fk_resource_type_service_type'
            ),
            mysql_engine='InnoDB',
            mysql_charset='utf8')
    resource = sql.Table(
            'resource', meta,
            sql.Column('id', sql.String(length=64), primary_key=True),
            sql.Column('name', sql.String(length=255), nullable=False),
            sql.Column('service_type', sql.String(length=255), nullable=False),
            sql.ForeignKeyConstraint(
                ['service_type'], ['service.type'],
                name='fk_resource_service_type'
            ),
            mysql_engine='InnoDB',
            mysql_charset='utf8')
    jio_policy = sql.Table(
            'jio_policy', meta,
            sql.Column('id', sql.String(length=64), primary_key=True),
            sql.Column('name', sql.String(length=255), nullable=False),
            sql.Column('project_id', sql.String(length=64), nullable=False),
            sql.Column('created_at', sql.DateTime, nullable=False),
            sql.Column('updated_at', sql.DateTime),
            sql.Column('deleted_at', sql.DateTime),
            sql.Column('policy_blob', key_sql.JsonBlob),
            mysql_engine='InnoDB',
            mysql_charset='utf8')
    policy_action_resource = sql.Table(
            'policy_action_resource', meta,
            sql.Column('policy_id', sql.String(length=64), nullable=False),
            sql.Column('action_id', sql.String(length=64), nullable=False),
            sql.Column('resource_id', sql.String(length=64), nullable=False),
            sql.Column('effect', sql.Boolean, default=False, nullable=False),
            sql.PrimaryKeyConstraint('policy_id', 'action_id', 'resource_id'),
            sql.ForeignKeyConstraint(
                ['action_id'], ['action.id'],
                name='fk_policy_action_id'
            ),
            sql.ForeignKeyConstraint(
                ['resource_id'], ['resource.id'],
                name='fk_policy_resource_id'
            ),
            sql.ForeignKeyConstraint(
                ['policy_id'], ['jio_policy.id'],
                name='fk_policy_action_resource_policy_id'
            ),
            mysql_engine='InnoDB',
            mysql_charset='utf8')
    policy_user_group_mapping = sql.Table(
            'policy_user_group_mapping', meta,
            sql.Column('type', sql.Enum(
                'UserPolicy',
                'GroupPolicy',
                name='type'),
                nullable=False),
            sql.Column('user_group_id', sql.String(64), nullable=False),
            sql.Column('policy_id', sql.String(64), nullable=False),
            sql.PrimaryKeyConstraint('type', 'user_group_id', 'policy_id'),
            sql.ForeignKeyConstraint(
                ['policy_id'], ['jio_policy.id'],
                name='fk_policy_user_group_policy_id'
            ),
            mysql_engine='InnoDB',
            mysql_charset='utf8')
    action_resource_type_mapping = sql.Table(
            'action_resource_type_mapping', meta,
            sql.Column('action_id', sql.String(length=64), nullable=False),
            sql.Column('resource_type_id', sql.String(length=64), nullable=False),
            sql.PrimaryKeyConstraint('action_id', 'resource_type_id'),
            sql.ForeignKeyConstraint(
                ['action_id'], ['action.id'],
                name='fk_mapping_action_id'
            ),
            sql.ForeignKeyConstraint(
                ['resource_type_id'], ['resource_type.id'],
                name='fk_mapping_resource_type_id'
            ),
            mysql_engine='InnoDB',
            mysql_charset='utf8')

    # create policy related tables
    tables = [action, resource_type, resource, jio_policy, policy_action_resource,
            policy_user_group_mapping, action_resource_type_mapping]
    for table in tables:
        try:
            table.create()
        except Exception:
            LOG.exception('Exception while creating table: %r', table)
            raise
