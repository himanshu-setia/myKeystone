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

import abc

from oslo_config import cfg
import six

from keystone.common import dependency
from keystone.common import manager
from keystone import exception
from keystone import notifications


CONF = cfg.CONF


@dependency.requires('identity_api', 'resource_api', 'jio_policy_api')
@dependency.provider('jio_role_api')
class Manager(manager.Manager):
    """Default pivot point for the Role backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.jio_role.driver)


    def create_role(self, account_id, role_id, role):
        ref = self.driver.create_role(account_id, role_id, role)
        return ref


    def delete_role(self, role_id):
        ref = self.driver.delete_role(role_id)


    # TODO(himanshu): Remove account_id from input params
    def update_role(self, account_id, role_id, role):
        return self.driver.update_role(account_id, role_id, role)


    def list_roles(self, account_id):
        return self.driver.list_roles(account_id)


    def get_role_summary(self, role_id):
	return self.driver.get_role_summary(role_id)

    def get_role(self, role_id):
	return self.driver.get_role(role_id)


@six.add_metaclass(abc.ABCMeta)
class Driver(object):

    @abc.abstractmethod
    def create_role(self, account_id, role_id, role):
        """Stores a role blob.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_role(self, role_id):
        """Deletes a role and all associated users.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_role(self, account_id, role_id, role):
        """Updates a role blob.

        :raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_role(self, role_id):
        """Gets a role blob.

        "raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_role_summary(self, role_id):
        """Gets all information related to the role

        "raises: keystone.exception.RoleNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_roles(self, account_id):
        """Lists roles in an account.

        "raises: No exceptions

        """
        raise exception.NotImplemented()


