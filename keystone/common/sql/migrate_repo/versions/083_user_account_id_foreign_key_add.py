import migrate
import sqlalchemy as sql
from migrate.changeset.constraint import ForeignKeyConstraint
from sqlalchemy.engine.reflection import Inspector

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    insp = Inspector.from_engine(migrate_engine)

    user_table = sql.Table('user', meta, autoload=True)
    user_constraint = insp.get_foreign_keys("user")
    user_account_fk_cons_exists = False
    for cons in user_constraint:
        if cons['name'] == 'fk_user_account_id':
            user_account_fk_cons_exists = True
            break

    if not user_account_fk_cons_exists:
        account_table = sql.Table('account', meta, autoload=True)
        cons = ForeignKeyConstraint([user_table.c.account_id], [account_table.c.id], name= 'fk_user_account_id')
        cons.create()
