from oslo_log import log
import sqlalchemy as sql

LOG = log.getLogger(__name__)

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user = sql.Table('user', meta, autoload=True)
    user.c.expiry.drop()


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    user = sql.Table('user', meta, autoload=True)
    user_expiry_colum = sql.Column('expiry', sql.DateTime)
    user_expiry_column.create(user)
