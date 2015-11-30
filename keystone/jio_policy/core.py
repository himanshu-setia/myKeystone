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

"""Entry point into the Jio policy service."""

import abc

from oslo_config import cfg
import six

from keystone.common import dependency
from keystone.common import manager
from keystone import exception
from keystone import notifications


CONF = cfg.CONF

@dependency.requires('identity_api')
@dependency.provider('jio_policy_api')
class Manager(manager.Manager):
    """Default pivot point for the Policy backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    _JIO_POLICY = 'jio_policy'

    def __init__(self):
        super(Manager, self).__init__(CONF.jio_policy.driver)

    def create_policy(self, service, project_id, policy_id, policy):
        ref = self.driver.create_policy(service, project_id, policy_id, policy)
        return ref

    def delete_policy(self, policy_id):
        ref = self.driver.delete_policy(policy_id)

    def attach_policy_to_user(self, policy_id, user_id):
        self.identity_api.get_user(user_id)
        self.driver.attach_policy_to_user(policy_id, user_id)

    def detach_policy_from_user(self, policy_id, user_id):
        self.identity_api.get_user(user_id)
        self.driver.detach_policy_from_user(policy_id, user_id)

    def attach_policy_to_group(self, policy_id, group_id):
        self.identity_api.get_group(group_id)
        self.driver.attach_policy_to_group(policy_id, group_id)

    def detach_policy_from_group(self, policy_id, group_id):
        self.identity_api.get_group(group_id)
        self.driver.detach_policy_from_group(policy_id, group_id)


@six.add_metaclass(abc.ABCMeta)
class Driver(object):

    @abc.abstractmethod
    def create_policy(self, service, project_id, policy_id, policy):
        """Store a policy blob.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_policy(self, policy_id):
        """Deletes a policy blob.

        :raises: keystone.exception.PolicyNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def attach_policy_to_user(self, policy_id, user_id):
        """Attaches a policy to a user.

        :raises: keystone.exception.PolicyNotFound
                 keystone.exception.UserNotFound
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def detach_policy_from_user(self, policy_id, user_id):
        """Detach policy from a user.

        :raises: keystone.exception.PolicyNotFound
                 keystone.exception.UserNotFound
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def attach_policy_to_group(self, policy_id, group_id):
        """Attaches a policy to a group.

        :raises: keystone.exception.PolicyNotFound
                 keystone.exception.GroupNotFound
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def detach_policy_from_group(self, policy_id, group_id):
        """Detaches policy from a group.

        :raises: keystone.exception.PolicyNotFound
                 keystone.exception.UserNotFound
        """
        raise exception.NotImplemented()
