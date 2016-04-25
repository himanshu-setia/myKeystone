from oslo_log import log
import sqlalchemy as sql
from keystone.common import sql as key_sql

LOG = log.getLogger(__name__)

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user = sql.Table('user', meta, autoload=True)
    account = sql.Table('account', meta, autoload=True)
    action = sql.Table('action', meta, autoload=True)

    preauth_token = sql.Table(
            'preauth_token', meta,
            sql.Column('id', sql.String(length=64), primary_key=True),
            sql.Column('user_id', sql.String(length=64), nullable=False),
            sql.Column('account_id', sql.String(length=64), nullable=False),
            sql.Column('action', sql.String(length=255), nullable=False),
            sql.Column('resource', sql.String(length=255), nullable=False),
            sql.Column('object_id', sql.String(length=255), nullable=True),
            sql.Column('expires', sql.DateTime),
            sql.ForeignKeyConstraint(
                ['user_id'], ['user.id'],
                name='fk_preauth_token_user_id'
            ),
            sql.ForeignKeyConstraint(
                ['account_id'], ['account.id'],
                name='fk_preauth_token_account_id'
            ),
            sql.ForeignKeyConstraint(
                ['action'], ['action.action_name'],
                name='fk_preauth_token_action'
            ),
            mysql_engine='InnoDB',
            mysql_charset='utf8')


    try:
       preauth_token.create()
    except Exception:
       LOG.exception('Exception while creating table: %r', preauth_token)
       raise
