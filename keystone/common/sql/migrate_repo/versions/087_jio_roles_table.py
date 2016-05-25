from oslo_log import log
import sqlalchemy as sql
from keystone.common import sql as key_sql
import datetime

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user = sql.Table('user', meta, autoload=True)
    account = sql.Table('account', meta, autoload=True)
    jio_policy= sql.Table('jio_policy', meta, autoload=True)

    jio_role = sql.Table(
            'jio_role', meta,
            sql.Column('id', sql.String(length=64), primary_key=True),
            sql.Column('name', sql.String(length=255), nullable=False, index=True),
            sql.Column('account_id', sql.String(length=64), nullable=False, index=True),
            sql.Column('trust_policy_blob', key_sql.JsonBlob),
            sql.Column('created_at', sql.DateTime, nullable=False, default=datetime.datetime.utcnow(), index=True),
            sql.Column('updated_at', sql.DateTime),
            sql.UniqueConstraint('name', 'account_id', name='ixu_jio_role_name_account_id'),
            sql.ForeignKeyConstraint(
                ['account_id'], ['account.id'],
                name='fk_jio_role_account_account_id'
            ),
            mysql_engine='InnoDB',
            mysql_charset='utf8')

    trust_policy_statement = sql.Table(
            'trust_policy_statement', meta,
            sql.Column('id', sql.String(length=64), primary_key=True),
            sql.Column('jio_role_id', sql.String(length=64), nullable=False),
            sql.Column('effect', sql.Boolean, default=False, nullable=False),
            sql.Column('principal_jrn', sql.String(length=255), nullable=False, index=True),
            sql.Column('type', sql.Enum(
                    'account',
                    'user',
                    'saml',
                    name='type'),
                nullable=False),
            sql.ForeignKeyConstraint(
                ['jio_role_id'], ['jio_role.id'],
                name='fk_trust_policy_statement_jio_role_id'
            ),
            mysql_engine='InnoDB',
            mysql_charset='utf8')

    jio_role_user = sql.Table(
            'jio_role_user', meta,
            sql.Column('id', sql.String(length=64), primary_key=True),
            sql.Column('extra', key_sql.JsonBlob),
            sql.Column('user_id', sql.String(length=64), nullable=False),
            sql.Column('account_id', sql.String(length=64), nullable=False),
            sql.Column('jio_role_id', sql.String(length=64), nullable=False),
            sql.Column('expiry', sql.DateTime, nullable=False, index=True),
            sql.Column('type', sql.Enum('jio_role', name='type'), nullable=False),
            sql.Column('created_at', sql.DateTime, nullable=False, default=datetime.datetime.utcnow(), index=True),
            sql.ForeignKeyConstraint(
                ['user_id'], ['user.id'],
                name='fk_jio_role_user_user_id'
            ),
            sql.ForeignKeyConstraint(
                ['account_id'], ['account.id'],
                name='fk_jio_role_user_account_id'
            ),
            sql.ForeignKeyConstraint(
                ['jio_role_id'], ['jio_role.id'],
                name='fk_jio_role_user_jio_role_id'
            ),
            mysql_engine='InnoDB',
            mysql_charset='utf8')

    jio_role_credentials = sql.Table(
            'jio_role_credentials', meta,
            sql.Column('id', sql.String(length=64), primary_key=True),
            sql.Column('jio_role_user_id', sql.String(length=64), nullable=False),
            sql.Column('account_id', sql.String(length=64), nullable=False),
            sql.Column('expires', sql.DateTime, nullable=False, index=True),
            sql.Column('type', sql.Enum(
                    'ec2',
                    name='type'),
                nullable=False),
            sql.Column('created_at', sql.DateTime, nullable=False, default=datetime.datetime.utcnow(), index=True),
            sql.Column('blob', key_sql.JsonBlob),
            sql.ForeignKeyConstraint(
                ['account_id'], ['account.id'],
                name='fk_jio_role_credentials_account_id'
            ),
            sql.ForeignKeyConstraint(
                ['jio_role_user_id'], ['jio_role_user.id'],
                name='fk_jio_role_credentials_jio_role_user_id'
            ),
            mysql_engine='InnoDB',
            mysql_charset='utf8')

    jio_role_token = sql.Table(
            'jio_role_token', meta,
            sql.Column('id', sql.String(length=70), nullable=False, primary_key=True),
            sql.Column('expires', sql.DateTime, nullable=False, index=True),
            sql.Column('extra', key_sql.JsonBlob),
            sql.Column('trust_id', sql.String(64), index=True),
            sql.Column('jio_role_user_id', sql.String(length=64), nullable=False),
            sql.Column('created_at', sql.DateTime, nullable=False, default=datetime.datetime.utcnow()),
            sql.ForeignKeyConstraint(
                ['jio_role_user_id'], ['jio_role_user.id'],
                name='fk_jio_role_token_jio_role_user_id'
            ),
            mysql_engine='InnoDB',
            mysql_charset='utf8')

    jio_role_policy_mapping = sql.Table(
            'jio_role_policy_mapping', meta,
            sql.Column('jio_role_id', sql.String(64), nullable=False),
            sql.Column('policy_id', sql.String(64), nullable=False),
            sql.ForeignKeyConstraint(
                ['jio_role_id'], ['jio_role.id'],
                name='fk_jio_role_policy_mapping_jio_role_id'
            ),
            sql.ForeignKeyConstraint(
                ['policy_id'], ['jio_policy.id'],
                name='fk_jio_role_policy_mapping_policy_id'
            ),
            sql.PrimaryKeyConstraint('jio_role_id', 'policy_id'),
            mysql_engine='InnoDB',
            mysql_charset='utf8')

    # create policy related tables
    tables = [jio_role, trust_policy_statement, jio_role_user, jio_role_credentials, jio_role_token, jio_role_policy_mapping]

    for table in tables:
        try:
            table.create()
        except Exception:
            LOG.exception('Exception while creating table: %r', table)
            raise
