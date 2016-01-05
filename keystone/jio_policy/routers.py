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
from keystone.common import router
from keystone.common import wsgi
from keystone.jio_policy import controllers
from keystone.common import json_home


class Routers(wsgi.RoutersBase):

    def append_v3_routers(self, mapper, routers):
        policy_controller = controllers.JioPolicyV3()

        self._add_resource(
            mapper, policy_controller,
            path='/jio_policies',
            post_action='create_policy',
            get_action='list_policies',
            rel=json_home.build_v3_resource_relation('jio_policies'),
            )

        self._add_resource(
            mapper, policy_controller,
            path='/jio_policies/{jio_policy_id}',
            delete_action='delete_policy',
            get_action='get_policy',
            patch_action='update_policy',
            rel=json_home.build_v3_resource_relation('jio_policy'),
            path_vars={
                'jio_policy_id': json_home.Parameters.JIO_POLICY_ID,
            })

        self._add_resource(
                mapper, policy_controller,
                path='/jio_policies/{jio_policy_id}/users/{user_id}',
                put_action='attach_policy_to_user',
                delete_action='detach_policy_from_user',
                rel=json_home.build_v3_resource_relation('jio_policy_user'),
                path_vars={
                    'jio_policy_id': json_home.Parameters.JIO_POLICY_ID,
                    'user_id': json_home.Parameters.USER_ID
                })

        self._add_resource(
                mapper, policy_controller,
                path='/jio_policies/{jio_policy_id}/groups/{group_id}',
                put_action='attach_policy_to_group',
                delete_action='detach_policy_from_group',
                rel=json_home.build_v3_resource_relation('jio_policy_group'),
                path_vars={
                    'jio_policy_id': json_home.Parameters.JIO_POLICY_ID,
                    'group_id': json_home.Parameters.GROUP_ID
                })
        
	self._add_resource(
                mapper, policy_controller,
                path='/actions',
                get_action='list_actions',
                rel=json_home.build_v3_resource_relation('jio_policy')
                )

        self._add_resource(
                mapper, policy_controller,
                path='/jio_policies/{jio_policy_id}/summary',
                get_action='get_policy_summary',
                rel=json_home.build_v3_resource_relation('jio_policy_summary'),
                path_vars={
                    'jio_policy_id': json_home.Parameters.JIO_POLICY_ID,
                })

