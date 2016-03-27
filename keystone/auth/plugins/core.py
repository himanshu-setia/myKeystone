# Copyright 2013 OpenStack Foundation
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

import sys

from oslo_config import cfg
from oslo_log import log
import six

from keystone.common import dependency
from keystone import exception

CONF = cfg.CONF
LOG = log.getLogger(__name__)


def construct_method_map_from_config():
    """Determine authentication method types for deployment.

    :returns: a dictionary containing the methods and their indexes

    """
    method_map = dict()
    method_index = 1
    for method in CONF.auth.methods:
        method_map[method_index] = method
        method_index = method_index * 2

    return method_map


def convert_method_list_to_integer(methods):
    """Convert the method type(s) to an integer.

    :param methods: a list of method names
    :returns: an integer representing the methods

    """
    method_map = construct_method_map_from_config()

    method_ints = []
    for method in methods:
        for k, v in six.iteritems(method_map):
            if v == method:
                method_ints.append(k)
    return sum(method_ints)


def convert_integer_to_method_list(method_int):
    """Convert an integer to a list of methods.

    :param method_int: an integer representing methods
    :returns: a corresponding list of methods

    """
    # If the method_int is 0 then no methods were used so return an empty
    # method list
    if method_int == 0:
        return []

    method_map = construct_method_map_from_config()
    method_ints = []
    for k, v in six.iteritems(method_map):
        method_ints.append(k)
    method_ints.sort(reverse=True)

    confirmed_methods = []
    for m_int in method_ints:
        # (lbragstad): By dividing the method_int by each key in the
        # method_map, we know if the division results in an integer of 1, that
        # key was used in the construction of the total sum of the method_int.
        # In that case, we should confirm the key value and store it so we can
        # look it up later. Then we should take the remainder of what is
        # confirmed and the method_int and continue the process. In the end, we
        # should have a list of integers that correspond to indexes in our
        # method_map and we can reinflate the methods that the original
        # method_int represents.
        if (method_int / m_int) == 1:
            confirmed_methods.append(m_int)
            method_int = method_int - m_int

    methods = []
    for method in confirmed_methods:
        methods.append(method_map[method])

    return methods


@dependency.requires('identity_api', 'resource_api')
class UserAuthInfo(object):

    @staticmethod
    def create(auth_payload, method_name):
        user_auth_info = UserAuthInfo()
        user_auth_info._validate_and_normalize_auth_data(auth_payload)
        user_auth_info.METHOD_NAME = method_name
        return user_auth_info

    def __init__(self):
        self.user_id = None
        self.password = None
        self.user_ref = None
        self.METHOD_NAME = None

    def _assert_account_is_enabled(self, account_ref):
        try:
            self.resource_api.assert_account_enabled(
                account_id=account_ref['id'],
                account=account_ref)
        except AssertionError as e:
            LOG.warning(six.text_type(e))
            six.reraise(exception.Unauthorized, exception.Unauthorized(e),
                        sys.exc_info()[2])

    def _assert_user_is_enabled(self, user_ref):
        try:
            self.identity_api.assert_user_enabled(
                user_id=user_ref['id'],
                user=user_ref)
        except AssertionError as e:
            LOG.warning(six.text_type(e))
            six.reraise(exception.Unauthorized, exception.Unauthorized(e),
                        sys.exc_info()[2])

    def _lookup_account(self, account_info):
        account_id = account_info.get('id')
        account_name = account_info.get('name')
        account_ref = None
        if not account_id and not account_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='account')
        try:
            if account_name:
                account_ref = self.resource_api.get_account_by_name(
                    account_name)
            else:
                account_ref = self.resource_api.get_account(account_id)
        except exception.AccountNotFound as e:
            LOG.exception(six.text_type(e))
            raise exception.Unauthorized(e)
        self._assert_account_is_enabled(account_ref)
        return account_ref

    def _validate_and_normalize_auth_data(self, auth_payload):
        if 'user' not in auth_payload:
            raise exception.ValidationError(attribute='user',
                                            target=self.METHOD_NAME)
        user_info = auth_payload['user']
        user_id = user_info.get('id')
        user_name = user_info.get('name')
        user_ref = None
        if not user_id and not user_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='user')
        self.password = user_info.get('password')
        try:
            if user_name:
                if 'account' not in user_info:
                    # check if user is root user
                    account_id = self.identity_api.get_account_if_name_root(user_name)
                    if account_id is None:
                        msg = 'Invalid username or password'
                        raise exception.Unauthorized(msg)
                    user_info['account'] = { "id": account_id}
                account_ref = self._lookup_account(user_info['account'])
                user_ref = self.identity_api.get_user_by_name(
                    user_name, account_ref['id'])
            else:
                user_ref = self.identity_api.get_user(user_id)
                account_ref = self.resource_api.get_account(
                    user_ref['account_id'])
                self._assert_account_is_enabled(account_ref)
        except exception.UserNotFound as e:
            LOG.exception(six.text_type(e))
            raise exception.Unauthorized(e)
        self._assert_user_is_enabled(user_ref)
        self.user_ref = user_ref
        self.user_id = user_ref['id']
        self.account_id = account_ref['id']
