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

from __future__ import absolute_import

import uuid

from oslo_config import cfg
from oslo_log import log

from keystone import clean
from keystone.common import driver_hints
from keystone.common import ldap as common_ldap
from keystone.common import models
from keystone import exception
from keystone.i18n import _
from keystone.identity.backends import ldap as ldap_identity
from keystone import resource


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class Resource(resource.Driver):
    def __init__(self):
        super(Resource, self).__init__()
        self.LDAP_URL = CONF.ldap.url
        self.LDAP_USER = CONF.ldap.user
        self.LDAP_PASSWORD = CONF.ldap.password
        self.suffix = CONF.ldap.suffix

        # This is the only deep dependency from resource back to identity.
        # This is safe to do since if you are using LDAP for resource, it is
        # required that you are using it for identity as well.
        self.user = ldap_identity.UserApi(CONF)

        self.project = ProjectApi(CONF)

    def default_assignment_driver(self):
        return 'keystone.assignment.backends.ldap.Assignment'

    def _set_default_parent_project(self, ref):
        """If the parent project ID has not been set, set it to None."""
        if isinstance(ref, dict):
            if 'parent_id' not in ref:
                ref = dict(ref, parent_id=None)
            return ref
        elif isinstance(ref, list):
            return [self._set_default_parent_project(x) for x in ref]
        else:
            raise ValueError(_('Expected dict or list: %s') % type(ref))

    def _validate_parent_project_is_none(self, ref):
        """If a parent_id different from None was given,
           raises InvalidProjectException.

        """
        parent_id = ref.get('parent_id')
        if parent_id is not None:
            raise exception.InvalidParentProject(parent_id)

    def _set_default_attributes(self, project_ref):
        project_ref = self._set_default_account(project_ref)
        return self._set_default_parent_project(project_ref)

    def get_project(self, tenant_id):
        return self._set_default_attributes(
            self.project.get(tenant_id))

    def list_projects(self, hints):
        return self._set_default_attributes(
            self.project.get_all_filtered(hints))

    def list_projects_in_account(self, account_id):
        # We don't support multiple accounts within this driver, so ignore
        # any account specified
        return self.list_projects(driver_hints.Hints())

    def list_projects_in_subtree(self, project_id):
        # We don't support projects hierarchy within this driver, so a
        # project will never have children
        return []

    def list_project_parents(self, project_id):
        # We don't support projects hierarchy within this driver, so a
        # project will never have parents
        return []

    def is_leaf_project(self, project_id):
        # We don't support projects hierarchy within this driver, so a
        # project will always be a root and a leaf at the same time
        return True

    def list_projects_from_ids(self, ids):
        return [self.get_project(id) for id in ids]

    def list_project_ids_from_account_ids(self, account_ids):
        # We don't support multiple accounts within this driver, so ignore
        # any account specified
        return [x.id for x in self.list_projects(driver_hints.Hints())]

    def get_project_by_name(self, tenant_name, account_id):
        self._validate_default_account_id(account_id)
        return self._set_default_attributes(
            self.project.get_by_name(tenant_name))

    def create_project(self, tenant_id, tenant):
        self.project.check_allow_create()
        tenant = self._validate_default_account(tenant)
        self._validate_parent_project_is_none(tenant)
        tenant['name'] = clean.project_name(tenant['name'])
        data = tenant.copy()
        if 'id' not in data or data['id'] is None:
            data['id'] = str(uuid.uuid4().hex)
        if 'description' in data and data['description'] in ['', None]:
            data.pop('description')
        return self._set_default_attributes(
            self.project.create(data))

    def update_project(self, tenant_id, tenant):
        self.project.check_allow_update()
        tenant = self._validate_default_account(tenant)
        if 'name' in tenant:
            tenant['name'] = clean.project_name(tenant['name'])
        return self._set_default_attributes(
            self.project.update(tenant_id, tenant))

    def delete_project(self, tenant_id):
        self.project.check_allow_delete()
        if self.project.subtree_delete_enabled:
            self.project.deleteTree(tenant_id)
        else:
            # The manager layer will call assignments to delete the
            # role assignments, so we just have to delete the project itself.
            self.project.delete(tenant_id)

    def create_account(self, account_id, account):
        if account_id == CONF.identity.default_account_id:
            msg = _('Duplicate ID, %s.') % account_id
            raise exception.Conflict(type='account', details=msg)
        raise exception.Forbidden(_('Accounts are read-only against LDAP'))

    def get_account(self, account_id):
        self._validate_default_account_id(account_id)
        return resource.calc_default_account()

    def update_account(self, account_id, account):
        self._validate_default_account_id(account_id)
        raise exception.Forbidden(_('Accounts are read-only against LDAP'))

    def delete_account(self, account_id):
        self._validate_default_account_id(account_id)
        raise exception.Forbidden(_('Accounts are read-only against LDAP'))

    def list_accounts(self, hints):
        return [resource.calc_default_account()]

    def list_accounts_from_ids(self, ids):
        return [resource.calc_default_account()]

    def get_account_by_name(self, account_name):
        default_account = resource.calc_default_account()
        if account_name != default_account['name']:
            raise exception.AccountNotFound(account_id=account_name)
        return default_account


# TODO(termie): turn this into a data object and move logic to driver
class ProjectApi(common_ldap.ProjectLdapStructureMixin,
                 common_ldap.EnabledEmuMixIn, common_ldap.BaseLdap):

    model = models.Project

    def create(self, values):
        data = values.copy()
        if data.get('id') is None:
            data['id'] = uuid.uuid4().hex
        return super(ProjectApi, self).create(data)

    def update(self, project_id, values):
        old_obj = self.get(project_id)
        return super(ProjectApi, self).update(project_id, values, old_obj)

    def get_all_filtered(self, hints):
        query = self.filter_query(hints)
        return super(ProjectApi, self).get_all(query)
