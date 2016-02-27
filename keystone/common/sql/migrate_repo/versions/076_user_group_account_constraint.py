import migrate
import sqlalchemy as sql
from migrate.changeset.constraint import UniqueConstraint
from sqlalchemy import create_engine
from sqlalchemy.engine.reflection import Inspector

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    insp = Inspector.from_engine(migrate_engine)

    user_constraint = insp.get_unique_constraints("user")
    for cons in user_constraint:
        if cons['name'] == 'ixu_user_name_account_id':
            user_cons_exists = True
            break

    if not user_cons_exists:
        user_table = sql.Table('user', meta, autoload=True)
        user_cons = UniqueConstraint('name', 'account_id', name='ixu_user_name_account_id', table=user_table)
        user_cons.create()

    group_constraint = insp.get_unique_constraints("group")
    for cons in group_constraint:
        if cons['name'] == 'ixu_group_name_account_id':
            group_cons_exists = True
            break
            
    if not group_cons_exists:     
        group_table = sql.Table('group', meta, autoload=True)
        group_cons = UniqueConstraint('name', 'account_id', name='ixu_group_name_account_id', table=group_table)
        group_cons.create()

    account_constraint = insp.get_unique_constraints("account")
    for cons in account_constraint:
        if cons['name'] == 'ixu_account_name':
            account_cons_exists = True
            break

    if not account_cons_exists:
        account_table = sql.Table('account', meta, autoload=True)
        account_cons = UniqueConstraint('name', name='ixu_account_name', table=account_table)
        account_cons.create()
