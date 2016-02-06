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
from oslo_log import log

from keystone import clean
from keystone.common import sql
from keystone import exception
from keystone.i18n import _LE
from keystone import resource as keystone_resource


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class Resource(keystone_resource.Driver):

    def default_assignment_driver(self):
        return 'keystone.assignment.backends.sql.Assignment'

    def _get_project(self, session, project_id):
        project_ref = session.query(Project).get(project_id)
        if project_ref is None:
            raise exception.ProjectNotFound(project_id=project_id)
        return project_ref

    def get_project(self, tenant_id):
        with sql.transaction() as session:
            return self._get_project(session, tenant_id).to_dict()

    def get_project_by_name(self, tenant_name, account_id):
        with sql.transaction() as session:
            query = session.query(Project)
            query = query.filter_by(name=tenant_name)
            query = query.filter_by(account_id=account_id)
            try:
                project_ref = query.one()
            except sql.NotFound:
                raise exception.ProjectNotFound(project_id=tenant_name)
            return project_ref.to_dict()

    @sql.truncated
    def list_projects(self, hints):
        with sql.transaction() as session:
            query = session.query(Project)
            project_refs = sql.filter_limit_query(Project, query, hints)
            return [project_ref.to_dict() for project_ref in project_refs]

    def list_projects_from_ids(self, ids):
        if not ids:
            return []
        else:
            with sql.transaction() as session:
                query = session.query(Project)
                query = query.filter(Project.id.in_(ids))
                return [project_ref.to_dict() for project_ref in query.all()]

    def list_project_ids_from_account_ids(self, account_ids):
        if not account_ids:
            return []
        else:
            with sql.transaction() as session:
                query = session.query(Project.id)
                query = (
                    query.filter(Project.account_id.in_(account_ids)))
                return [x.id for x in query.all()]

    def list_projects_in_account(self, account_id):
        with sql.transaction() as session:
            self._get_account(session, account_id)
            query = session.query(Project)
            project_refs = query.filter_by(account_id=account_id)
            return [project_ref.to_dict() for project_ref in project_refs]

    def _get_children(self, session, project_ids):
        query = session.query(Project)
        query = query.filter(Project.parent_id.in_(project_ids))
        project_refs = query.all()
        return [project_ref.to_dict() for project_ref in project_refs]

    def list_projects_in_subtree(self, project_id):
        with sql.transaction() as session:
            project = self._get_project(session, project_id).to_dict()
            children = self._get_children(session, [project['id']])
            subtree = []
            examined = set(project['id'])
            while children:
                children_ids = set()
                for ref in children:
                    if ref['id'] in examined:
                        msg = _LE('Circular reference or a repeated '
                                  'entry found in projects hierarchy - '
                                  '%(project_id)s.')
                        LOG.error(msg, {'project_id': ref['id']})
                        return
                    children_ids.add(ref['id'])

                examined.union(children_ids)
                subtree += children
                children = self._get_children(session, children_ids)
            return subtree

    def list_project_parents(self, project_id):
        with sql.transaction() as session:
            project = self._get_project(session, project_id).to_dict()
            parents = []
            examined = set()
            while project.get('parent_id') is not None:
                if project['id'] in examined:
                    msg = _LE('Circular reference or a repeated '
                              'entry found in projects hierarchy - '
                              '%(project_id)s.')
                    LOG.error(msg, {'project_id': project['id']})
                    return

                examined.add(project['id'])
                parent_project = self._get_project(
                    session, project['parent_id']).to_dict()
                parents.append(parent_project)
                project = parent_project
            return parents

    def is_leaf_project(self, project_id):
        with sql.transaction() as session:
            project_refs = self._get_children(session, [project_id])
            return not project_refs

    # CRUD
    @sql.handle_conflicts(conflict_type='project')
    def create_project(self, tenant_id, tenant):
        tenant['name'] = clean.project_name(tenant['name'])
        with sql.transaction() as session:
            tenant_ref = Project.from_dict(tenant)
            session.add(tenant_ref)
            return tenant_ref.to_dict()

    @sql.handle_conflicts(conflict_type='project')
    def update_project(self, tenant_id, tenant):
        if 'name' in tenant:
            tenant['name'] = clean.project_name(tenant['name'])

        with sql.transaction() as session:
            tenant_ref = self._get_project(session, tenant_id)
            old_project_dict = tenant_ref.to_dict()
            for k in tenant:
                old_project_dict[k] = tenant[k]
            new_project = Project.from_dict(old_project_dict)
            for attr in Project.attributes:
                if attr != 'id':
                    setattr(tenant_ref, attr, getattr(new_project, attr))
            tenant_ref.extra = new_project.extra
            return tenant_ref.to_dict(include_extra_dict=True)

    @sql.handle_conflicts(conflict_type='project')
    def delete_project(self, tenant_id):
        with sql.transaction() as session:
            tenant_ref = self._get_project(session, tenant_id)
            session.delete(tenant_ref)

    # account crud

    @sql.handle_conflicts(conflict_type='account')
    def create_account(self, account_id, account):
        # default type for account is customer account
        account['type']=account.get('type','ca')
        with sql.transaction() as session:
            ref = Account.from_dict(account)
            session.add(ref)
        return ref.to_dict()

    def duplicate(self, account_id):
        with sql.transaction() as session:
            query = session.query(Account)
            query.filter(Account.id == account_id)
            account_refs = query.all()
            if account_refs == None or account_refs == []:
                return True
            else:
                return False

    @sql.truncated
    def list_accounts(self, hints):
        with sql.transaction() as session:
            query = session.query(Account)
            refs = sql.filter_limit_query(Account, query, hints)
            return [ref.to_dict() for ref in refs]

    def list_accounts_from_ids(self, ids):
        if not ids:
            return []
        else:
            with sql.transaction() as session:
                query = session.query(Account)
                query = query.filter(Account.id.in_(ids))
                account_refs = query.all()
                return [account_ref.to_dict() for account_ref in account_refs]

    def _get_account(self, session, account_id):
        ref = session.query(Account).get(account_id)
        if ref is None:
            raise exception.AccountNotFound(account_id=account_id)
        return ref

    def get_account(self, account_id):
        with sql.transaction() as session:
            return self._get_account(session, account_id).to_dict()

    def get_account_by_name(self, account_name):
        with sql.transaction() as session:
            try:
                ref = (session.query(Account).
                       filter_by(name=account_name).one())
            except sql.NotFound:
                raise exception.AccountNotFound(account_id=account_name)
            return ref.to_dict()

    @sql.handle_conflicts(conflict_type='account')
    def update_account(self, account_id, account):
        # default type for account is customer account
        account['type']=account.get('type','ca')
        with sql.transaction() as session:
            ref = self._get_account(session, account_id)
            old_dict = ref.to_dict()
            for k in account:
                old_dict[k] = account[k]
            new_account = Account.from_dict(old_dict)
            for attr in Account.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_account, attr))
            ref.extra = new_account.extra
            return ref.to_dict()

    def delete_account(self, account_id):
        with sql.transaction() as session:
            ref = self._get_account(session, account_id)
            session.delete(ref)

    def is_account_console(self, account_id):
        with sql.transaction() as session:
           account = self._get_account(session, account_id).to_dict()
           return account.get('type') == 'console'
        return False

class Account(sql.ModelBase, sql.DictBase):
    __tablename__ = 'account'
    attributes = ['id', 'name', 'enabled', 'extra', 'type']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    enabled = sql.Column(sql.Boolean, default=True, nullable=False)
    extra = sql.Column(sql.JsonBlob())
    type = sql.Column(sql.Enum('ca', 'console', 'csa', 'isa'), nullable=False)
    __table_args__ = (sql.UniqueConstraint('name'), {})


class Project(sql.ModelBase, sql.DictBase):
    __tablename__ = 'project'
    attributes = ['id', 'name', 'account_id', 'description', 'enabled',
                  'parent_id']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    account_id = sql.Column(sql.String(64), sql.ForeignKey('account.id'),
                           nullable=False)
    description = sql.Column(sql.Text())
    enabled = sql.Column(sql.Boolean)
    extra = sql.Column(sql.JsonBlob())
    parent_id = sql.Column(sql.String(64), sql.ForeignKey('project.id'))
    # Unique constraint across two columns to create the separation
    # rather than just only 'name' being unique
    __table_args__ = (sql.UniqueConstraint('account_id', 'name'), {})
