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

"""Keystone External Authentication Plugins"""

import abc

from oslo_config import cfg
import six

from keystone import auth
from keystone.common import dependency
from keystone import exception
from keystone.i18n import _
from keystone.openstack.common import versionutils


CONF = cfg.CONF


@six.add_metaclass(abc.ABCMeta)
class Base(auth.AuthMethodHandler):

    method = 'external'

    def authenticate(self, context, auth_info, auth_context):
        """Use REMOTE_USER to look up the user in the identity backend.

        auth_context is an in-out variable that will be updated with the
        user_id from the actual user from the REMOTE_USER env variable.
        """
        try:
            REMOTE_USER = context['environment']['REMOTE_USER']
        except KeyError:
            msg = _('No authenticated user')
            raise exception.Unauthorized(msg)
        try:
            user_ref = self._authenticate(REMOTE_USER, context)
            auth_context['user_id'] = user_ref['id']
            if ('kerberos' in CONF.token.bind and
                (context['environment'].get('AUTH_TYPE', '').lower()
                 == 'negotiate')):
                auth_context['bind']['kerberos'] = user_ref['name']
        except Exception:
            msg = _('Unable to lookup user %s') % (REMOTE_USER)
            raise exception.Unauthorized(msg)

    @abc.abstractmethod
    def _authenticate(self, remote_user, context):
        """Look up the user in the identity backend.

        Return user_ref
        """
        pass


@dependency.requires('identity_api')
class DefaultAccount(Base):
    def _authenticate(self, remote_user, context):
        """Use remote_user to look up the user in the identity backend."""
        account_id = CONF.identity.default_account_id
        user_ref = self.identity_api.get_user_by_name(remote_user, account_id)
        return user_ref


@dependency.requires('identity_api', 'resource_api')
class Account(Base):
    def _authenticate(self, remote_user, context):
        """Use remote_user to look up the user in the identity backend.

        The account will be extracted from the REMOTE_ACCOUNT environment
        variable if present. If not, the default account will be used.
        """

        username = remote_user
        try:
            account_name = context['environment']['REMOTE_ACCOUNT']
        except KeyError:
            account_id = CONF.identity.default_account_id
        else:
            account_ref = self.resource_api.get_account_by_name(account_name)
            account_id = account_ref['id']

        user_ref = self.identity_api.get_user_by_name(username, account_id)
        return user_ref


@dependency.requires('assignment_api', 'identity_api')
class KerberosAccount(Account):
    """Allows `kerberos` as a method."""
    method = 'kerberos'

    def _authenticate(self, remote_user, context):
        auth_type = context['environment'].get('AUTH_TYPE')
        if auth_type != 'Negotiate':
            raise exception.Unauthorized(_("auth_type is not Negotiate"))
        return super(KerberosAccount, self)._authenticate(remote_user, context)


class ExternalDefault(DefaultAccount):
    """Deprecated. Please use keystone.auth.external.DefaultAccount instead."""

    @versionutils.deprecated(
        as_of=versionutils.deprecated.ICEHOUSE,
        in_favor_of='keystone.auth.external.DefaultAccount',
        remove_in=+1)
    def __init__(self):
        super(ExternalDefault, self).__init__()


class ExternalAccount(Account):
    """Deprecated. Please use keystone.auth.external.Account instead."""

    @versionutils.deprecated(
        as_of=versionutils.deprecated.ICEHOUSE,
        in_favor_of='keystone.auth.external.Account',
        remove_in=+1)
    def __init__(self):
        super(ExternalAccount, self).__init__()


@dependency.requires('identity_api')
class LegacyDefaultAccount(Base):
    """Deprecated. Please use keystone.auth.external.DefaultAccount instead.

    This plugin exists to provide compatibility for the unintended behavior
    described here: https://bugs.launchpad.net/keystone/+bug/1253484

    """

    @versionutils.deprecated(
        as_of=versionutils.deprecated.ICEHOUSE,
        in_favor_of='keystone.auth.external.DefaultAccount',
        remove_in=+1)
    def __init__(self):
        super(LegacyDefaultAccount, self).__init__()

    def _authenticate(self, remote_user, context):
        """Use remote_user to look up the user in the identity backend."""
        # NOTE(dolph): this unintentionally discards half the REMOTE_USER value
        names = remote_user.split('@')
        username = names.pop(0)
        account_id = CONF.identity.default_account_id
        user_ref = self.identity_api.get_user_by_name(username, account_id)
        return user_ref


@dependency.requires('identity_api', 'resource_api')
class LegacyAccount(Base):
    """Deprecated. Please use keystone.auth.external.Account instead."""

    @versionutils.deprecated(
        as_of=versionutils.deprecated.ICEHOUSE,
        in_favor_of='keystone.auth.external.Account',
        remove_in=+1)
    def __init__(self):
        super(LegacyAccount, self).__init__()

    def _authenticate(self, remote_user, context):
        """Use remote_user to look up the user in the identity backend.

        If remote_user contains an `@` assume that the substring before the
        rightmost `@` is the username, and the substring after the @ is the
        account name.
        """
        names = remote_user.rsplit('@', 1)
        username = names.pop(0)
        if names:
            account_name = names[0]
            account_ref = self.resource_api.get_account_by_name(account_name)
            account_id = account_ref['id']
        else:
            account_id = CONF.identity.default_account_id
        user_ref = self.identity_api.get_user_by_name(username, account_id)
        return user_ref
