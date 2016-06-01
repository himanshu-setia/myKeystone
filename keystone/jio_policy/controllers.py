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
from keystone.jio_policy import schema
from keystone import exception

@dependency.requires('jio_policy_api','identity_api')
class JioPolicyV3(controller.V3Controller):
    collection_name = 'policies'
    member_name = 'policy'

    def list_actions(self, context):
        ref = self.jio_policy_api.list_actions()
        return ref

    @controller.jio_policy_filterprotected(args='Policy')
    @validation.validated(schema.policy_create, 'policy')
    def create_policy(self, context, policy):
        policy_id = uuid.uuid4().hex
        try:
            account_id = context['environment']['KEYSTONE_AUTH_CONTEXT'][
                'account_id']
        except KeyError:
            raise exception.Forbidden('Cannot find account_id in context.')
        account_policies_limit = self.resource_api.get_account_users_limit(account_id)
        account_policies_cnt = self.jio_policy_api.get_policies_count_in_account(account_id)
        if account_policies_cnt >= account_policies_limit:
            raise exception.Forbidden(
                'Maximum limit reached for number of policies in the account. Only %s policies are permitted'
                %account_policies_limit)
        policy = self.jio_policy_api.create_policy(account_id, policy_id,
                                                   policy)
        return JioPolicyV3.wrap_member(context, policy)

    @controller.jio_policy_filterprotected(args='Policy')
    @validation.validated(schema.policy_create, 'policy')
    def create_resource_based_policy(self, context, policy):
        policy_id = uuid.uuid4().hex
        try:
            project_id = context['environment']['KEYSTONE_AUTH_CONTEXT'][
                'project_id']
        except KeyError:
            raise exceptions.Forbidden()
        policy = self.jio_policy_api.create_resource_based_policy(project_id, policy_id,
                                                   policy)
        return JioPolicyV3.wrap_member(context, policy)

    @controller.jio_policy_filterprotected(args='Policy')
    def list_policies(self, context):
        try:
            account_id = context['environment']['KEYSTONE_AUTH_CONTEXT'][
                'account_id']
        except KeyError:
            raise exception.Forbidden('Cannot find account_id in context.')
        ref = self.jio_policy_api.list_policies(account_id)
        return JioPolicyV3.wrap_collection(context, ref)

    @controller.jio_policy_filterprotected(args='Policy')
    def list_resource_based_policies(self, context):
        try:
            account_id = context['environment']['KEYSTONE_AUTH_CONTEXT'][
                'account_id']
        except KeyError:
            raise exception.Forbidden('Cannot find account_id in context.')
        ref = self.jio_policy_api.list_resource_based_policies(account_id)
        return JioPolicyV3.wrap_collection(context, ref)

    @controller.jio_policy_filterprotected(args='Policy')
    def get_policy(self, context, jio_policy_id):
        ref = self.jio_policy_api.get_policy(jio_policy_id)
        return JioPolicyV3.wrap_member(context, ref)

    @controller.jio_policy_filterprotected(args='Policy')
    def get_resource_based_policy(self, context, jio_policy_id):
        ref = self.jio_policy_api.get_resource_based_policy(jio_policy_id)
        return JioPolicyV3.wrap_member(context, ref)

    @controller.jio_policy_filterprotected(args='Policy')
    def delete_policy(self, context, jio_policy_id):
        return self.jio_policy_api.delete_policy(jio_policy_id)

    @controller.jio_policy_filterprotected(args='Policy')
    def delete_resource_based_policy(self, context, jio_policy_id):
        return self.jio_policy_api.delete_resource_based_policy(jio_policy_id)

    @controller.jio_policy_filterprotected(args='Policy')
    @validation.validated(schema.policy_update, 'policy')
    def update_policy(self, context, jio_policy_id, policy):
        try:
            account_id = context['environment']['KEYSTONE_AUTH_CONTEXT'][
                'account_id']
        except KeyError:
            raise exception.Forbidden('Cannot find account_id in context.')
        ref = self.jio_policy_api.update_policy(account_id, jio_policy_id, policy)
        return JioPolicyV3.wrap_member(context, ref)

    @controller.jio_policy_filterprotected(args='Policy')
    @validation.validated(schema.policy_update, 'policy')
    def update_resource_based_policy(self, context, jio_policy_id, policy):
        ref = self.jio_policy_api.update_resource_based_policy(jio_policy_id, policy)
        return JioPolicyV3.wrap_member(context, ref)

    @controller.jio_policy_filterprotected(args=['Policy','User'])
    def attach_policy_to_user(self, context, jio_policy_id, user_id):
        ref = self.identity_api.get_user(user_id)
        account_id = ref.get('account_id')
        account_user_attach_policy_limit = self.resource_api.get_account_user_attach_policy_limit(account_id)
        account_user_attach_policy_cnt = self.jio_policy_api.get_user_attach_policy_count_in_account(user_id)
        if account_user_attach_policy_cnt >= account_user_attach_policy_limit:
            raise exception.Forbidden(
                'Maximum limit reached for number policies to be attached to user in the account. Only %s policies are permitted'
                %account_user_attach_policy_limit)

        if ref.get('type') == 'root':
            raise exception.Forbidden('Policy cannot be attached to root user')

        return self.jio_policy_api.attach_policy_to_user(jio_policy_id,
                                                         user_id)

    @controller.jio_policy_filterprotected(args=['Policy','User'])
    def detach_policy_from_user(self, context, jio_policy_id, user_id):
        ref = self.identity_api.get_user(user_id)
        if ref.get('type') == 'root':
            raise exception.Forbidden('Policy cannot be detached from root user')
        return self.jio_policy_api.detach_policy_from_user(jio_policy_id,
                                                           user_id)

    @controller.jio_policy_filterprotected(args=['Policy','Group'])
    def attach_policy_to_group(self, context, jio_policy_id, group_id):
        ref = self.identity_api.get_group(group_id)
        account_id = ref.get('account_id')
        account_group_attach_policy_limit = self.resource_api.get_account_group_attach_policy_limit(account_id)
        account_group_attach_policy_cnt = self.jio_policy_api.get_group_attach_policy_count_in_account(group_id)
        if account_group_attach_policy_cnt >= account_group_attach_policy_limit:
            raise exception.Forbidden(
                'Maximum limit reached for number policies to be attached to group in the account. Only %s policies are permitted'
                %account_group_attach_policy_limit)
        return self.jio_policy_api.attach_policy_to_group(jio_policy_id,
                                                          group_id)

    @controller.jio_policy_filterprotected(args=['Policy','Group'])
    def detach_policy_from_group(self, context, jio_policy_id, group_id):
        return self.jio_policy_api.detach_policy_from_group(jio_policy_id,
                                                            group_id)

    @controller.jio_policy_filterprotected(args=['Policy'])
    def attach_policy_to_resource(self, context, jio_policy_id, resource):
        try:
            account_id = context['environment']['KEYSTONE_AUTH_CONTEXT'][
                'account_id']
        except KeyError:
            raise exception.Forbidden('Cannot find account_id in context.')
        return self.jio_policy_api.attach_policy_to_resource(jio_policy_id, account_id,
                                                         resource)

    @controller.jio_policy_filterprotected(args=['Policy'])
    def detach_policy_from_resource(self, context, jio_policy_id, resource):
        return self.jio_policy_api.detach_policy_from_resource(jio_policy_id,
                                                           resource)

    @controller.jio_policy_filterprotected(args=['Policy','Role'])
    def attach_policy_to_role(self, context, jio_policy_id, jio_role_id):
        return self.jio_policy_api.attach_policy_to_role(jio_policy_id,
                                                         jio_role_id)

    @controller.jio_policy_filterprotected(args=['Policy','Role'])
    def detach_policy_from_role(self, context, jio_policy_id, jio_role_id):
        return self.jio_policy_api.detach_policy_from_role(jio_policy_id,
                                                           jio_role_id)

    @controller.jio_policy_filterprotected(args='Policy')
    def get_policy_summary(self, context, jio_policy_id):
        refs = self.jio_policy_api.get_policy_summary(jio_policy_id)

        sum_list = refs['attached_entities']
        for ref in sum_list:

            if ref['type'] == 'UserPolicy':
                ref['user_name'] = (self.identity_api.get_user(ref['id']))['name']
            else:
                ref['group_name'] = (self.identity_api.get_group(ref['id']))['name']

        return refs

    @controller.jio_policy_filterprotected(args='Policy')
    def get_resource_based_policy_summary(self, context, jio_policy_id):
        refs = self.jio_policy_api.get_resource_based_policy_summary(jio_policy_id)
        return refs

    @controller.isa_protected()
    def create_action(self, context, action_name):
        action_id = uuid.uuid4().hex
        ls = action_name.split(':')
        if len(ls) < 4:
            raise exception.ValidationError(attribute='action name', target='action_name')

        service = ls[2]
        if service == None:
                raise exception.ValidationError(attribute='Service name cannot be null.', target = 'service')
        action = ls[3]
        if action == None or (action != '*' and (action.isalpha() is False or action[0].isupper() is False)):
            raise exception.ValidationError(attribute='Action name should contain only alphabets and in pascal case.', target='action_name')

        ref = self.jio_policy_api.create_action(action_id, action_name, service)
        return {'Action':ref}

    @controller.isa_protected()
    def create_resource_type(self, context, resource_type, service):
        resource_type_id = uuid.uuid4().hex
        if service == None:
                raise exception.ValidationError(attribute='Service name cannot be null.', target = 'service')
        if resource_type == None or (
                resource_type != '*' and (
                    resource_type.isalpha() is False or resource_type[0].isupper() is False)):
            raise exception.ValidationError(
                            attribute='Resource type name should contain only alphabets and in pascal case.',
                            target='ResourceType')

        ref = self.jio_policy_api.create_resource_type(resource_type_id, resource_type, service)
        return {'Resource_type':ref}

    @controller.isa_protected()
    def create_action_resource_type_mapping(self, context, action_name, resource_type_name, resource_type_service):
        ref = self.jio_policy_api.create_action_resource_type_mapping(action_name, resource_type_name, resource_type_service)
        return {'Action_Resource_type_Mapping':ref}
