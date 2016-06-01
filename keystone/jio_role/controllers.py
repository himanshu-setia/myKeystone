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

import uuid

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone import notifications
from keystone.jio_role import schema
from keystone import exception

@dependency.requires('jio_role_api','identity_api')
class JioRoleV3(controller.V3Controller):
    collection_name = 'roles'
    member_name = 'role'

    @controller.jio_policy_filterprotected(args='Role')
    @validation.validated(schema.role_create, 'role')
    def create_role(self, context, role):
        role_id = uuid.uuid4().hex
        try:
            account_id = context['environment']['KEYSTONE_AUTH_CONTEXT'][
                                 'account_id']
        except KeyError:
            raise exception.Forbidden('Cannot find account_id in context.')
        role = self.jio_role_api.create_role(account_id, role_id,
                                                   role)
        return JioRoleV3.wrap_member(context, role)


    @controller.jio_policy_filterprotected(args='Role')
    @validation.validated(schema.role_update, 'role')
    def update_role(self, context, jio_role_id, role):
        try:
            account_id = context['environment']['KEYSTONE_AUTH_CONTEXT'][
                'account_id']
        except KeyError:
            raise exception.Forbidden('Cannot find account_id in context.')
        ref = self.jio_role_api.update_role(account_id, jio_role_id, role)
        return JioRoleV3.wrap_member(context, ref)


    @controller.jio_policy_filterprotected(args='Role')
    def delete_role(self, context, jio_role_id):
        return self.jio_role_api.delete_role(jio_role_id)


    @controller.jio_policy_filterprotected(args='Role')
    def get_role_summary(self, context, jio_role_id):
        refs = self.jio_role_api.get_role_summary(jio_role_id)

        """sum_list = refs['attached_entities']
        for ref in sum_list:

            if ref['type'] == 'UserPolicy':
                ref['user_name'] = (self.identity_api.get_user(ref['id']))['name']
            else:
                ref['group_name'] = (self.identity_api.get_group(ref['id']))['name']"""
        return refs


    @controller.jio_policy_filterprotected(args='Role')
    def list_roles(self, context):
        try:
            account_id = context['environment']['KEYSTONE_AUTH_CONTEXT'][
                'account_id']
        except KeyError:
            raise exception.Forbidden('Cannot find account_id in context.')
        return self.jio_role_api.list_roles(account_id)


