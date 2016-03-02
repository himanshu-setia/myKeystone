# Copyright 2013 Metacloud, Inc.
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

"""Workflow Logic the Resource service."""

import uuid
import random

from oslo_config import cfg
from oslo_log import log

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone.common import wsgi
from keystone import exception
from keystone.i18n import _
from keystone import notifications
from keystone.resource import schema
from keystone.common import utils
from oslo_serialization import jsonutils

CONF = cfg.CONF
LOG = log.getLogger(__name__)

naming_pre = 'jrn:jcs:'
root_action = 'jrn:jcs:*'
root_resource = 'jrn:jcs:*:'

def _unique_account_id():
    x=12
    id = '{0:0{x}d}'.format(random.randint(0, 10**x-1), x=x)
    return id.rjust(32, '0')

@dependency.requires('resource_api')
class Tenant(controller.V2Controller):

    @controller.v2_deprecated
    def get_all_projects(self, context, **kw):
        """Gets a list of all tenants for an admin user."""
        if 'name' in context['query_string']:
            return self.get_project_by_name(
                context, context['query_string'].get('name'))

        self.assert_admin(context)
        tenant_refs = self.resource_api.list_projects_in_account(
            CONF.identity.default_account_id)
        for tenant_ref in tenant_refs:
            tenant_ref = self.v3_to_v2_project(tenant_ref)
        params = {
            'limit': context['query_string'].get('limit'),
            'marker': context['query_string'].get('marker'),
        }
        return self.format_project_list(tenant_refs, **params)

    @controller.v2_deprecated
    def get_project(self, context, tenant_id):
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(context)
        ref = self.resource_api.get_project(tenant_id)
        return {'tenant': self.v3_to_v2_project(ref)}

    @controller.v2_deprecated
    def get_project_by_name(self, context, tenant_name):
        self.assert_admin(context)
        ref = self.resource_api.get_project_by_name(
            tenant_name, CONF.identity.default_account_id)
        return {'tenant': self.v3_to_v2_project(ref)}

    # CRUD Extension
    @controller.v2_deprecated
    def create_project(self, context, tenant):
        tenant_ref = self._normalize_dict(tenant)

        if 'name' not in tenant_ref or not tenant_ref['name']:
            msg = _('Name field is required and cannot be empty')
            raise exception.ValidationError(message=msg)

        self.assert_admin(context)
        tenant_ref['id'] = tenant_ref.get('id', uuid.uuid4().hex)
        initiator = notifications._get_request_audit_info(context)
        tenant = self.resource_api.create_project(
            tenant_ref['id'],
            self._normalize_account_id(context, tenant_ref),
            initiator)
        return {'tenant': self.v3_to_v2_project(tenant)}

    @controller.v2_deprecated
    def update_project(self, context, tenant_id, tenant):
        self.assert_admin(context)
        # Remove account_id if specified - a v2 api caller should not
        # be specifying that
        clean_tenant = tenant.copy()
        clean_tenant.pop('account_id', None)
        initiator = notifications._get_request_audit_info(context)
        tenant_ref = self.resource_api.update_project(
            tenant_id, clean_tenant, initiator)
        return {'tenant': self.v3_to_v2_project(tenant_ref)}

    @controller.v2_deprecated
    def delete_project(self, context, tenant_id):
        self.assert_admin(context)
        initiator = notifications._get_request_audit_info(context)
        self.resource_api.delete_project(tenant_id, initiator)


@dependency.requires('resource_api', 'identity_api', 'jio_policy_api', 'credential_api')
class AccountV3(controller.V3Controller):
    collection_name = 'accounts'
    member_name = 'account'

    def __init__(self):
        super(AccountV3, self).__init__()
        self.get_member_from_driver = self.resource_api.get_account

    def attach_root_policy(self, user_id, account_id):
        # For root user, account id is same as user id
        resource = root_resource + account_id +':*'
        jio_policy = dict()
        jio_policy['id'] = uuid.uuid4().hex
        jio_policy['name'] = 'root_policy_'+user_id
        statement = dict()
        statement['action'] = [root_action]
        statement['resource'] =[resource]
        statement['effect'] = 'allow'
        jio_policy['statement'] = [statement]
        policy = self.jio_policy_api.create_policy(account_id, jio_policy.get('id'), jio_policy, True)
        self.jio_policy_api.attach_policy_to_user(policy.get('id'), user_id)

    def create_account(self, context, account):
        ref = self._assign_unique_id(self._normalize_dict(account))
        initiator = notifications._get_request_audit_info(context)
        user_ref = dict()
        user_ref['id'] =  ref['id']
        ref['id'] = _unique_account_id()
        # Check if not duplicate
        while self.resource_api.duplicate(ref['id']):
            ref['id'] = _unique_account_id()
        ref.pop('password')
        ref = self.resource_api.create_account(ref['id'], ref, initiator)
        project = dict()
        project['account_id'] = ref['id']
        project['name'] = ref['name']
        project['id'] = ref['id']
        project = self.resource_api.create_project(ref['id'], project,
                                          initiator=initiator)
        user_ref['account_id'] = ref['id']
        user_ref['name'] = ref['name']
        if 'password' in account and account.get('password') is not None:
            user_ref['password'] = account.get('password')
        user_ref['type'] = 'root'
        user = self.identity_api.create_user(user_ref, initiator=None)
        self.attach_root_policy(user.get('id'), user_ref['account_id'])
        if ref.get('type') == None:
            ref.pop('type')
        return ref, user.get('id')

    @controller.console_protected()
    @validation.validated(schema.account_create, 'account')
    def create_customer_account(self, context, account):
        ref, user_id = self.create_account(context, account)
        return AccountV3.wrap_member(context, ref)

    @controller.isa_protected_for_create_console_acc()
    @validation.validated(schema.account_create, 'account')
    def create_console_account(self, context, account):
        ref, user_id = self.create_account(context, account)
        #create credentials for the root user.
        blob = {'access': uuid.uuid4().hex,
                'secret': uuid.uuid4().hex }
        credential_id = utils.hash_access_key(blob['access'])
        cred_ref = {'user_id': user_id,
                    'project_id': ref['id'],
                    'blob': jsonutils.dumps(blob),
                    'id': credential_id,
                    'type': 'ec2'}

        self.credential_api.create_credential(credential_id, cred_ref)
        ref['credentials'] = cred_ref.get('blob')
        return AccountV3.wrap_member(context, ref)

    @controller.isa_protected()
    def update_service_account(self, context, services, account_id, user_ids=None):
        if account_id is None:
            msg = 'Cannot upgrade without account id'
        if not isinstance(services, list):
            services = services.split()

        if user_ids == None:
            user_ids = []
            user = self.identity_api.get_root_user(account_id)
            user_ids.append(user.get('id'))
        actions = []
        resources = []
        for s in services:
            action = naming_pre + s +':*'
            actions.append(action)
            resources.append(action)

        jio_policy = dict()
        jio_policy['id'] = uuid.uuid4().hex
        account_id_len = len(account_id)
        if account_id_len > 12:
            len_to_trunc = account_id_len-12
        else:
            len_to_trunc = 0
        jio_policy['name'] = 'csa_ubp_' + account_id[len_to_trunc:] + '_' + uuid.uuid4().hex
        statement = dict()
        statement['action'] = actions
        statement['resource'] =resources
        statement['effect'] = 'allow'
        jio_policy['statement'] = [statement]
        policy = self.jio_policy_api.create_policy(account_id, jio_policy.get('id'), jio_policy, True, True)
        for id in user_ids:
            self.jio_policy_api.attach_policy_to_user(policy.get('id'), id)
        return self.resource_api.update_account_type(account_id, 'csa')

    @controller.filterprotected('enabled', 'name')
    def list_accounts(self, context, filters):
        hints = AccountV3.build_driver_hints(context, filters)
        refs = self.resource_api.list_accounts(hints=hints)
        return AccountV3.wrap_collection(context, refs, hints=hints)

    def get_account(self, context, account_id):
        ref = self.resource_api.get_account(account_id)
        return AccountV3.wrap_member(context, ref)

    @validation.validated(schema.account_update, 'account')
    def update_account(self, context, account_id, account):
        self._require_matching_id(account_id, account)
        initiator = notifications._get_request_audit_info(context)
        ref = self.resource_api.update_account(account_id, account, initiator)
        return AccountV3.wrap_member(context, ref)

    @controller.jio_policy_filterprotected(args='Account')
    def delete_account(self, context, account_id):
        initiator = notifications._get_request_audit_info(context)
        return self.resource_api.delete_account(account_id, initiator)


@dependency.requires('account_config_api')
class AccountConfigV3(controller.V3Controller):
    member_name = 'config'

    @controller.protected()
    def create_account_config(self, context, account_id, config):
        original_config = (
            self.account_config_api.get_config_with_sensitive_info(account_id))
        ref = self.account_config_api.create_config(account_id, config)
        if original_config:
            # Return status code 200, since config already existed
            return wsgi.render_response(body={self.member_name: ref})
        else:
            return wsgi.render_response(body={self.member_name: ref},
                                        status=('201', 'Created'))

    @controller.protected()
    def get_account_config(self, context, account_id, group=None, option=None):
        ref = self.account_config_api.get_config(account_id, group, option)
        return {self.member_name: ref}

    @controller.protected()
    def update_account_config(
            self, context, account_id, config, group, option):
        ref = self.account_config_api.update_config(
            account_id, config, group, option)
        return wsgi.render_response(body={self.member_name: ref})

    def update_account_config_group(self, context, account_id, group, config):
        return self.update_account_config(
            context, account_id, config, group, option=None)

    def update_account_config_only(self, context, account_id, config):
        return self.update_account_config(
            context, account_id, config, group=None, option=None)

    @controller.protected()
    def delete_account_config(
            self, context, account_id, group=None, option=None):
        self.account_config_api.delete_config(account_id, group, option)


@dependency.requires('resource_api')
class ProjectV3(controller.V3Controller):
    collection_name = 'projects'
    member_name = 'project'

    def __init__(self):
        super(ProjectV3, self).__init__()
        self.get_member_from_driver = self.resource_api.get_project

    @controller.protected()
    @validation.validated(schema.project_create, 'project')
    def create_project(self, context, project):
        ref = self._assign_unique_id(self._normalize_dict(project))
        ref = self._normalize_account_id(context, ref)
        initiator = notifications._get_request_audit_info(context)
        ref = self.resource_api.create_project(ref['id'], ref,
                                               initiator=initiator)
        return ProjectV3.wrap_member(context, ref)

    @controller.filterprotected('account_id', 'enabled', 'name',
                                'parent_id')
    def list_projects(self, context, filters):
        hints = ProjectV3.build_driver_hints(context, filters)
        refs = self.resource_api.list_projects(hints=hints)
        return ProjectV3.wrap_collection(context, refs, hints=hints)

    def _expand_project_ref(self, context, ref):
        params = context['query_string']

        parents_as_list = 'parents_as_list' in params and (
            self.query_filter_is_true(params['parents_as_list']))
        parents_as_ids = 'parents_as_ids' in params and (
            self.query_filter_is_true(params['parents_as_ids']))

        subtree_as_list = 'subtree_as_list' in params and (
            self.query_filter_is_true(params['subtree_as_list']))
        subtree_as_ids = 'subtree_as_ids' in params and (
            self.query_filter_is_true(params['subtree_as_ids']))

        # parents_as_list and parents_as_ids are mutually exclusive
        if parents_as_list and parents_as_ids:
            msg = _('Cannot use parents_as_list and parents_as_ids query '
                    'params at the same time.')
            raise exception.ValidationError(msg)

        # subtree_as_list and subtree_as_ids are mutually exclusive
        if subtree_as_list and subtree_as_ids:
            msg = _('Cannot use subtree_as_list and subtree_as_ids query '
                    'params at the same time.')
            raise exception.ValidationError(msg)

        user_id = self.get_auth_context(context).get('user_id')

        if parents_as_list:
            parents = self.resource_api.list_project_parents(
                ref['id'], user_id)
            ref['parents'] = [ProjectV3.wrap_member(context, p)
                              for p in parents]
        elif parents_as_ids:
            ref['parents'] = self.resource_api.get_project_parents_as_ids(ref)

        if subtree_as_list:
            subtree = self.resource_api.list_projects_in_subtree(
                ref['id'], user_id)
            ref['subtree'] = [ProjectV3.wrap_member(context, p)
                              for p in subtree]
        elif subtree_as_ids:
            ref['subtree'] = self.resource_api.get_projects_in_subtree_as_ids(
                ref['id'])

    @controller.protected()
    def get_project(self, context, project_id):
        ref = self.resource_api.get_project(project_id)
        self._expand_project_ref(context, ref)
        return ProjectV3.wrap_member(context, ref)

    @controller.protected()
    @validation.validated(schema.project_update, 'project')
    def update_project(self, context, project_id, project):
        self._require_matching_id(project_id, project)
        self._require_matching_account_id(
            project_id, project, self.resource_api.get_project)
        initiator = notifications._get_request_audit_info(context)
        ref = self.resource_api.update_project(project_id, project,
                                               initiator=initiator)
        return ProjectV3.wrap_member(context, ref)

    @controller.protected()
    def delete_project(self, context, project_id):
        initiator = notifications._get_request_audit_info(context)
        return self.resource_api.delete_project(project_id,
                                                initiator=initiator)
