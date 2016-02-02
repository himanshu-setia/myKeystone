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

"""WSGI Routers for the Assignment service."""

import functools

from oslo_config import cfg

from keystone.assignment import controllers
from keystone.common import json_home
from keystone.common import router
from keystone.common import wsgi


CONF = cfg.CONF

build_os_inherit_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-INHERIT', extension_version='1.0')


class Public(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        tenant_controller = controllers.TenantAssignment()
        mapper.connect('/tenants',
                       controller=tenant_controller,
                       action='get_projects_for_token',
                       conditions=dict(method=['GET']))


class Admin(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        # Role Operations
        # Commented (roopali) to mute role functionality
        roles_controller = controllers.RoleAssignmentV2()
        #mapper.connect('/tenants/{tenant_id}/users/{user_id}/roles',
        #               controller=roles_controller,
        #               action='get_user_roles',
        #               conditions=dict(method=['GET']))
        #mapper.connect('/users/{user_id}/roles',
        #               controller=roles_controller,
        #               action='get_user_roles',
        #               conditions=dict(method=['GET']))


class Routers(wsgi.RoutersBase):

    def append_v3_routers(self, mapper, routers):

        project_controller = controllers.ProjectAssignmentV3()
        self._add_resource(
            mapper, project_controller,
            path='/users/{user_id}/projects',
            get_action='list_user_projects',
            rel=json_home.build_v3_resource_relation('user_projects'),
            path_vars={
                'user_id': json_home.Parameters.USER_ID,
            })
