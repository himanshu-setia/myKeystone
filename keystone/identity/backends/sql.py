# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_config import cfg

from keystone.common import sql
from keystone.common import utils
from keystone import exception
from keystone.i18n import _
from keystone import identity
import datetime;

CONF = cfg.CONF


class User(sql.ModelBase, sql.DictBase):
    __tablename__ = 'user'
    attributes = ['id', 'name', 'account_id', 'password', 'enabled',
                  'default_project_id', 'type']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(255), nullable=False)
    account_id = sql.Column(sql.String(64), nullable=False)
    password = sql.Column(sql.String(128))
    enabled = sql.Column(sql.Boolean)
    extra = sql.Column(sql.JsonBlob())
    default_project_id = sql.Column(sql.String(64))
    type = sql.Column(sql.Enum('regular', 'root'), nullable=False)
    # Unique constraint across two columns to create the separation
    # rather than just only 'name' being unique
    __table_args__ = (sql.UniqueConstraint('account_id', 'name'), {})

    def to_dict(self, include_extra_dict=False):
        d = super(User, self).to_dict(include_extra_dict=include_extra_dict)
        if 'default_project_id' in d and d['default_project_id'] is None:
            del d['default_project_id']
        return d


class UserHistory(sql.ModelBase, sql.DictBase):
    __tablename__ = 'user_history'
    attributes = ['id', 'userid', 'password', 'date']
    id = sql.Column(sql.Integer, primary_key=True, nullable=False, autoincrement=True)
    userid = sql.Column(sql.String(64), sql.ForeignKey('user.id'), nullable=False)
    password = sql.Column(sql.String(128), nullable=False)
    date = sql.Column(sql.DateTime, nullable=False)
    __table_args__ = (sql.UniqueConstraint('userid', 'password'), {})


class Group(sql.ModelBase, sql.DictBase):
    __tablename__ = 'group'
    attributes = ['id', 'name', 'account_id', 'description']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    account_id = sql.Column(sql.String(64), nullable=False)
    description = sql.Column(sql.Text())
    extra = sql.Column(sql.JsonBlob())
    # Unique constraint across two columns to create the separation
    # rather than just only 'name' being unique
    __table_args__ = (sql.UniqueConstraint('account_id', 'name'), {})


class UserGroupMembership(sql.ModelBase, sql.DictBase):
    """Group membership join table."""
    __tablename__ = 'user_group_membership'
    user_id = sql.Column(sql.String(64),
                         sql.ForeignKey('user.id'),
                         primary_key=True)
    group_id = sql.Column(sql.String(64),
                          sql.ForeignKey('group.id'),
                          primary_key=True)


class Identity(identity.Driver):
    # NOTE(henry-nash): Override the __init__() method so as to take a
    # config parameter to enable sql to be used as a account-specific driver.
    def __init__(self, conf=None):
        super(Identity, self).__init__()

    def default_assignment_driver(self):
        return "keystone.assignment.backends.sql.Assignment"

    @property
    def is_sql(self):
        return True

    def _check_password(self, password, user_ref):
        """Check the specified password against the data store.

        Note that we'll pass in the entire user_ref in case the subclass
        needs things like user_ref.get('name')
        For further justification, please see the follow up suggestion at
        https://blueprints.launchpad.net/keystone/+spec/sql-identiy-pam

        """
        return utils.check_password(password, user_ref.password)

    # Identity interface
    def authenticate(self, user_id, password):
        session = sql.get_session()
        user_ref = None
        try:
            user_ref = self._get_user(session, user_id)
        except exception.UserNotFound:
            raise AssertionError(_('Invalid user / password'))
        if not self._check_password(password, user_ref):
            raise AssertionError(_('Invalid user / password'))
        return identity.filter_user(user_ref.to_dict())

    # user crud

    @sql.handle_conflicts(conflict_message='User already exists')
    def create_user(self, user_id, user):
        user = utils.hash_user_password(user)
        user['type']=user.get('type', 'regular')
        session = sql.get_session()
        with session.begin():
            user_ref = User.from_dict(user)
            session.add(user_ref)
            if 'password' in user:
                session.add(UserHistory(userid=user_ref['id'],
                                        password=user['password'],
                                        date=datetime.datetime.now()))
        return identity.filter_user(user_ref.to_dict())

    @sql.truncated
    def list_users(self, hints, account_id):
        session = sql.get_session()
        query = session.query(User)
        query = query.filter_by(account_id = account_id)
        query = query.filter_by(type = 'regular')
        user_refs = sql.filter_limit_query(User, query, hints)
        ref_list = []
        for ref in user_refs:
            dict = ref.to_dict()
            dict['group_count'] = self.count_groups_for_user(ref.id)
            if not dict['password']:
                dict['password'] = 'No'
            else:
                dict['password'] = 'Yes'
            ref_list.append(dict)

        return ref_list

    def get_users_count_in_account(self, account_id):
        session = sql.get_session()
        count = session.query(User).filter_by(account_id = account_id).count()
        return count

    def get_user_summary_for_group(self, group_id):
        session = sql.get_session()
        group = self._get_group(session,group_id)
        query = session.query(User.id,User.name).join(UserGroupMembership)
        query = query.filter(UserGroupMembership.group_id == group_id)

        ref_list = {}
        ref_list['group_id'] = group.id
        ref_list['group_name'] = group.name
        ref_list['group_description'] = group.description
        ref_list['group_jrn'] = 'jrn:jcs:iam:' + group.account_id + ':Group:' + group.name
        ref_list['attached_users'] = query.count()

        dict_list = []
        for ref in query:
            dict = {}
            dict['id'] = ref.id
            dict['name'] = ref.name
            dict_list.append(dict)

        ref_list['users'] = dict_list
        return ref_list

    def get_group_summary_for_user(self, user_id):
        session = sql.get_session()
        user = self._get_user(session,user_id)
        query = session.query(Group.id,Group.name).join(UserGroupMembership)
        query = query.filter(UserGroupMembership.user_id == user_id)

        ref_list = {}
        ref_list['user_id'] = user.id
        ref_list['user_name'] = user.name
        ref_list['user_jrn'] = 'jrn:jcs:iam:' + user.account_id + ':User:' + user.name
        ref_list['has_password'] = ('No','Yes')[user.password is not None]
        ref_list['attached_groups'] = query.count()

        dict_list = []
        for ref in query:
            dict = {}
            dict['id'] = ref.id
            dict['name'] = ref.name
            dict_list.append(dict)

        ref_list['groups'] = dict_list
        return ref_list

    def _get_user(self, session, user_id):
        user_ref = session.query(User).get(user_id)
        if not user_ref:
            raise exception.UserNotFound(user_id=user_id)
        return user_ref

    def get_unfiltered_user(self, user_id):
        session = sql.get_session()
        return self._get_user(session, user_id).to_dict()

    def get_user(self, user_id):
        session = sql.get_session()
        return identity.filter_user(self._get_user(session, user_id).to_dict())

    def get_root_user(self, account_id):
        session = sql.get_session()
        query = session.query(User)
        query = query.filter_by(account_id=account_id)
        query = query.filter_by(type = 'root')
        try:
            user_ref = query.one()
        except sql.NotFound:
            raise exception.RootUserNotFound(account_id=account_id)
        return identity.filter_user(user_ref.to_dict())

    def get_account_if_name_root(self, user_name):
        session = sql.get_session()
        query = session.query(User)
        query = query.filter_by(name=user_name)
        query = query.filter_by(type = 'root')
        try:
            user_ref = query.one()
        except sql.NotFound:
            return
        return user_ref.to_dict().get('account_id')


    def get_user_by_name(self, user_name, account_id):
        session = sql.get_session()
        query = session.query(User)
        query = query.filter_by(name=user_name)
        query = query.filter_by(account_id=account_id)
        try:
            user_ref = query.one()
        except sql.NotFound:
            raise exception.UserNotFound(user_id=user_name)
        return identity.filter_user(user_ref.to_dict())

    @sql.handle_conflicts(conflict_message='User already exists')
    def update_user(self, user_id, user):
        session = sql.get_session()
        with session.begin():
            user_ref = self._get_user(session, user_id)
            old_user_dict = user_ref.to_dict()
            user = utils.hash_user_password(user)
            for k in user:
                old_user_dict[k] = user[k]
            new_user = User.from_dict(old_user_dict)
            for attr in User.attributes:
                if attr != 'id':
                    setattr(user_ref, attr, getattr(new_user, attr))
            user_ref.extra = new_user.extra
        return identity.filter_user(user_ref.to_dict(include_extra_dict=True))

    def _get_user_history(self, session, user_id, count=0):
        query = session.query(UserHistory)
        query = query.filter_by(userid=user_id).order_by(UserHistory.date.desc())
        if count is not None and count is not 0:
            query = query.limit(count)
        try:
            user_refs = query.all()
        except sql.NotFound:
            raise exception.UserNotFound(userid=user_id)
        if not user_refs:
            return None
        return user_refs

    def get_user_history(self, user_id, count):
        session = sql.get_session()
        user_history = self._get_user_history(session, user_id, count)
        if user_history is not None:
            return user_history
        else:
            return None

    @sql.handle_conflicts(conflict_message='user_history')
    def update_user_history(self, user_id, original_password, count=0, hashed=False):
        session = sql.get_session()
        if hashed is False:
            original_password = utils.hash_password(original_password)
        with session.begin():
            user_history_refs = self._get_user_history(session, user_id)
            if user_history_refs:
                h_user_cnt = len(user_history_refs)
                if h_user_cnt is not 0 and h_user_cnt >= count:
                    user = user_history_refs[count-1]
                    new_row = {}
                    new_row['password'] = original_password
                    new_row['date'] =  datetime.datetime.utcnow()
                    session.query(UserHistory).filter(UserHistory.id == user.id).update(new_row, synchronize_session=False)
                    if h_user_cnt > count:
                        ## deleting the redundant user history
                        uids = []
                        for x in range(count, h_user_cnt):
                            uids.append(user_history_refs[x].id)
                        if uids and len(uids) > 0:
                            session.query(UserHistory).filter(UserHistory.id.in_(uids)).delete(synchronize_session=False)
                else:
                    session.add(UserHistory(userid=user_id,
                                            password=original_password,
                                            date=datetime.datetime.now()))

            else:
                session.add(UserHistory(userid=user_id,
                                            password=original_password,
                                            date=datetime.datetime.utcnow()))

    @sql.handle_conflicts(conflict_message='Cannot add user to group as user is already a member of group')
    def add_user_to_group(self, user_id, group_id):
        session = sql.get_session()
        self.get_group(group_id)
        ref = self._get_user(session, user_id)
        if ref.type == 'root':
            raise exception.Forbidden(message='Cannot add root user to a group')
        with session.begin():
            session.add(UserGroupMembership(user_id=user_id,
                                            group_id=group_id))

    def get_group_users_count_in_account(self, group_id):
        session = sql.get_session()
        self.get_group(group_id)
        query = session.query(UserGroupMembership)
        query = query.filter_by(group_id=group_id)
        count = query.count()
        return count

    def get_user_assign_group_count(self, user_id):
        session = sql.get_session()
        self.get_user(user_id)
        query = session.query(UserGroupMembership)
        query = query.filter_by(user_id=user_id)
        count = query.count()
        return count

    def check_user_in_group(self, user_id, group_id):
        session = sql.get_session()
        self.get_group(group_id)
        self.get_user(user_id)
        query = session.query(UserGroupMembership)
        query = query.filter_by(user_id=user_id)
        query = query.filter_by(group_id=group_id)
        if not query.first():
            raise exception.NotFound(_("User '%(user_id)s' not found in"
                                       " group '%(group_id)s'") %
                                     {'user_id': user_id,
                                      'group_id': group_id})

    def remove_user_from_group(self, user_id, group_id):
        session = sql.get_session()
        # We don't check if user or group are still valid and let the remove
        # be tried anyway - in case this is some kind of clean-up operation
        query = session.query(UserGroupMembership)
        query = query.filter_by(user_id=user_id)
        query = query.filter_by(group_id=group_id)
        membership_ref = query.first()
        if membership_ref is None:
            # Check if the group and user exist to return descriptive
            # exceptions.
            self.get_group(group_id)
            self.get_user(user_id)
            raise exception.NotFound(_("User '%(user_id)s' not found in"
                                       " group '%(group_id)s'") %
                                     {'user_id': user_id,
                                      'group_id': group_id})
        with session.begin():
            session.delete(membership_ref)

    def remove_user_membership(self, user_id):
        session = sql.get_session()
        # We don't check if user or group are still valid and let the remove
        # be tried anyway - in case this is some kind of clean-up operation
        query = session.query(UserGroupMembership)
        refs = query.filter_by(user_id=user_id)
        if refs is None:
            return
        with session.begin():
            session.query(UserGroupMembership).filter_by(user_id=user_id).delete()

    def remove_group_membership(self, group_id):
        session = sql.get_session()
        # We don't check if user or group are still valid and let the remove
        # be tried anyway - in case this is some kind of clean-up operation
        query = session.query(UserGroupMembership)
        refs = query.filter_by(group_id=group_id)
        if refs is None:
            return
        with session.begin():
            session.query(UserGroupMembership).filter_by(group_id=group_id).delete()

    def list_groups_for_user(self, user_id, hints):
        # TODO(henry-nash) We could implement full filtering here by enhancing
        # the join below.  However, since it is likely to be a fairly rare
        # occurrence to filter on more than the user_id already being used
        # here, this is left as future enhancement and until then we leave
        # it for the controller to do for us.
        session = sql.get_session()
        self.get_user(user_id)
        query = session.query(Group).join(UserGroupMembership)
        query = query.filter(UserGroupMembership.user_id == user_id)
        return [g.to_dict() for g in query]


    def count_groups_for_user(self, user_id):
        session = sql.get_session()
        query = session.query(UserGroupMembership)
        query = query.filter(UserGroupMembership.user_id == user_id)

        return query.count()

    def list_users_in_group(self, group_id, hints):
        # TODO(henry-nash) We could implement full filtering here by enhancing
        # the join below.  However, since it is likely to be a fairly rare
        # occurrence to filter on more than the group_id already being used
        # here, this is left as future enhancement and until then we leave
        # it for the controller to do for us.
        session = sql.get_session()
        self.get_group(group_id)
        query = session.query(User).join(UserGroupMembership)
        query = query.filter(UserGroupMembership.group_id == group_id)

        return [identity.filter_user(u.to_dict()) for u in query]


    def count_users_in_group(self, group_id):
        session = sql.get_session()
        query = session.query(UserGroupMembership)
        query = query.filter(UserGroupMembership.group_id == group_id)

        return query.count()

    def delete_user(self, user_id):
        session = sql.get_session()

        with session.begin():
            ref = self._get_user(session, user_id)
            if ref.type == 'root':
                raise exception.Forbidden(message='Cannot delete root user.')
            q = session.query(UserGroupMembership)
            q = q.filter_by(user_id=user_id)
            q.delete(False)

            q = session.query(UserHistory)
            q = q.filter_by(userid=user_id)
            q.delete(False)
            session.delete(ref)

    # group crud

    @sql.handle_conflicts(conflict_message='Group already exists')
    def create_group(self, group_id, group):
        session = sql.get_session()
        with session.begin():
            ref = Group.from_dict(group)
            session.add(ref)
        return ref.to_dict()

    @sql.truncated
    def list_groups(self, hints, account_id):
        session = sql.get_session()
        query = session.query(Group).filter_by(account_id = account_id)
        refs = sql.filter_limit_query(Group, query, hints)

        ref_list = []
        for ref in refs:
            dict = ref.to_dict()
            dict['user_count'] = self.count_users_in_group(ref.id)
            ref_list.append(dict)

        return ref_list

    def _get_group(self, session, group_id):
        ref = session.query(Group).get(group_id)
        if not ref:
            raise exception.GroupNotFound(group_id=group_id)
        return ref

    def get_group(self, group_id):
        session = sql.get_session()
        return self._get_group(session, group_id).to_dict()

    def get_groups_count_in_account(self, account_id):
        session = sql.get_session()
        count = session.query(Group).filter_by(account_id = account_id).count()
        return count

    def get_group_by_name(self, group_name, account_id):
        session = sql.get_session()
        query = session.query(Group)
        query = query.filter_by(name=group_name)
        query = query.filter_by(account_id=account_id)
        try:
            group_ref = query.one()
        except sql.NotFound:
            raise exception.GroupNotFound(group_id=group_name)
        return group_ref.to_dict()

    @sql.handle_conflicts(conflict_message='Group already exists')
    def update_group(self, group_id, group):
        session = sql.get_session()

        with session.begin():
            ref = self._get_group(session, group_id)
            old_dict = ref.to_dict()
            for k in group:
                old_dict[k] = group[k]
            new_group = Group.from_dict(old_dict)
            for attr in Group.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_group, attr))
            ref.extra = new_group.extra
        return ref.to_dict()

    def delete_group(self, group_id):
        session = sql.get_session()

        with session.begin():
            ref = self._get_group(session, group_id)

            q = session.query(UserGroupMembership)
            q = q.filter_by(group_id=group_id)
            q.delete(False)

            session.delete(ref)
