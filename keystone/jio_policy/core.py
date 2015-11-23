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

"""Entry point into the Policy service."""

import abc

from oslo_config import cfg
import six

from keystone.common import dependency
from keystone.common import manager
from keystone import exception
from keystone import notifications


CONF = cfg.CONF


@dependency.provider('jio_policy_api')
class Manager(manager.Manager):
    """Default pivot point for the Policy backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.policy'

    _POLICY = 'policy'

    def __init__(self):
        super(Manager, self).__init__(CONF.policy.driver)

    def create_policy(self, policy_id, policy, initiator=None):
        ref = self.driver.create_policy(policy_id, policy)
        notifications.Audit.created(self._POLICY, policy_id, initiator)
        return ref


@six.add_metaclass(abc.ABCMeta)
class PolicyDriverV8(object):

    @abc.abstractmethod
    def create_policy(self, policy_id, policy):
        """Store a policy blob.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover


Driver = manager.create_legacy_driver(PolicyDriverV8)
