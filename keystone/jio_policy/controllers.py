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

    #@controller.jio_policy_filterprotected(args='Policy')
    @validation.validated(schema.policy_create, 'policy')
    def create_policy(self, context, policy):
        try:
            project_id = context['environment']['KEYSTONE_AUTH_CONTEXT'][
                'project_id']
        except KeyError:
            raise exception.Forbidden()
        policy = self.jio_policy_api.create_policy(project_id, policy_id,
                                                   policy)
        return JioPolicyV3.wrap_member(context, policy)

    #@controller.jio_policy_filterprotected(args='Policy')
    def list_policies(self, context):
        try:
            project_id = context['environment']['KEYSTONE_AUTH_CONTEXT'][
                'project_id']
        except KeyError:
            raise exception.Forbidden()
        ref = self.jio_policy_api.list_policies(project_id)
        return JioPolicyV3.wrap_collection(context, ref)

    #@controller.jio_policy_filterprotected(args='Policy')
    def get_policy(self, context, jio_policy_id):
        ref = self.jio_policy_api.get_policy(jio_policy_id)
        return JioPolicyV3.wrap_member(context, ref)

    #@controller.jio_policy_filterprotected(args='Policy')
    def delete_policy(self, context, jio_policy_id):
        return self.jio_policy_api.delete_policy(jio_policy_id)

    #@controller.jio_policy_filterprotected(args='Policy')
    @validation.validated(schema.policy_update, 'policy')
    def update_policy(self, context, jio_policy_id, policy):
        ref = self.jio_policy_api.update_policy(jio_policy_id, policy)
        return JioPolicyV3.wrap_member(context, ref)

    #@controller.jio_policy_filterprotected(args=['Policy','User'])
    def attach_policy_to_user(self, context, jio_policy_id, user_id):
        return self.jio_policy_api.attach_policy_to_user(jio_policy_id,
                                                         user_id)

    #@controller.jio_policy_filterprotected(args=['Policy','User'])
    def detach_policy_from_user(self, context, jio_policy_id, user_id):
        return self.jio_policy_api.detach_policy_from_user(jio_policy_id,
                                                           user_id)

    #@controller.jio_policy_filterprotected(args=['Policy','Group'])
    def attach_policy_to_group(self, context, jio_policy_id, group_id):
        return self.jio_policy_api.attach_policy_to_group(jio_policy_id,
                                                          group_id)

    #@controller.jio_policy_filterprotected(args=['Policy','Group'])
    def detach_policy_from_group(self, context, jio_policy_id, group_id):
        return self.jio_policy_api.detach_policy_from_group(jio_policy_id,
                                                            group_id)

    #@controller.protected()
    def get_policy_summary(self, context, jio_policy_id):
        refs = self.jio_policy_api.list_policy_summary(jio_policy_id)

        sum_list = refs['Attached Entities']
        for ref in sum_list:
	    
            if ref['Type'] == 'UserPolicy':
                ref['Entity Name'] = (self.identity_api.get_user(ref['Entity Name']))['name']
            else:
                ref['Entity Name'] = (self.identity_api.get_group(ref['Entity Name']))['name']

        return refs

