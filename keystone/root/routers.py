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
"""WSGI Routers for the Identity service."""

from keystone.common import json_home
from keystone.common import router
from keystone.common import wsgi
from keystone.root import controllers


class Routers(wsgi.RoutersBase):

    def append_v3_routers(self, mapper, routers):
        root_controller = controllers.RootV3()
	
	self._add_resource(
          mapper, root_controller,
          path='/',
          get_action='genericmapper',
          rel=json_home.build_v3_resource_relation('genericmapper'),
          )
