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
from keystone.policy import schema


@dependency.requires('jio_policy_api')
class JioPolicyV3(controller.V3Controller):
    collection_name = 'policies'
    member_name = 'policy'

    @controller.protected()
    #@validation.validated(schema.policy_create, 'policy')
    def create_policy(self, context, policy):
        import pdb; pdb.set_trace()
        policy_id = uuid.uuid4().hex
        try:
            project_id = context['environment']['KEYSTONE_AUTH_CONTEXT']['project_id']
        except KeyError:
            raise exceptions.Forbidden()
        service = 'image'
        policy = self.jio_policy_api.create_policy(service, project_id, policy_id, policy)
        return policy
