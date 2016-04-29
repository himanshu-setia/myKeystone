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
from datetime import datetime, timedelta
from urlparse import parse_qs, urlparse
from keystoneclient.common import cms
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import importutils
from oslo_utils import timeutils
import six

from keystone.common import controller
from keystone.common import dependency
from keystone.common import wsgi
from keystone.common import utils
from keystone import config
from keystone.contrib import federation
from keystone import exception
from keystone.i18n import _, _LI, _LW
from keystone.resource import controllers as resource_controllers
import datetime as dtime
from keystone.common import utils

LOG = log.getLogger(__name__)

CONF = cfg.CONF

# registry of authentication methods
AUTH_METHODS = {}
AUTH_PLUGINS_LOADED = False


def load_auth_methods():
    global AUTH_PLUGINS_LOADED

    if AUTH_PLUGINS_LOADED:
        # Only try and load methods a single time.
        return
    # config.setup_authentication should be idempotent, call it to ensure we
    # have setup all the appropriate configuration options we may need.
    config.setup_authentication()
    for plugin in CONF.auth.methods:
        if '.' in plugin:
            # NOTE(morganfainberg): if '.' is in the plugin name, it should be
            # imported rather than used as a plugin identifier.
            plugin_class = plugin
            driver = importutils.import_object(plugin)
            if not hasattr(driver, 'method'):
                raise ValueError(_('Cannot load an auth-plugin by class-name '
                                   'without a "method" attribute defined: %s'),
                                 plugin_class)

            LOG.info(_LI('Loading auth-plugins by class-name is deprecated.'))
            plugin_name = driver.method
        else:
            plugin_name = plugin
            plugin_class = CONF.auth.get(plugin)
            driver = importutils.import_object(plugin_class)
        if plugin_name in AUTH_METHODS:
            raise ValueError(_('Auth plugin %(plugin)s is requesting '
                               'previously registered method %(method)s') %
                             {'plugin': plugin_class, 'method': driver.method})
        AUTH_METHODS[plugin_name] = driver
    AUTH_PLUGINS_LOADED = True


def get_auth_method(method_name):
    global AUTH_METHODS
    if method_name not in AUTH_METHODS:
        raise exception.AuthMethodNotSupported()
    return AUTH_METHODS[method_name]


class AuthContext(dict):
    """Retrofitting auth_context to reconcile identity attributes.

    The identity attributes must not have conflicting values among the
    auth plug-ins. The only exception is `expires_at`, which is set to its
    earliest value.

    """

    # identity attributes need to be reconciled among the auth plugins
    IDENTITY_ATTRIBUTES = frozenset(['user_id', 'project_id',
                                     'access_token_id', 'account_id',
                                     'expires_at'])

    def __setitem__(self, key, val):
        if key in self.IDENTITY_ATTRIBUTES and key in self:
            existing_val = self[key]
            if key == 'expires_at':
                # special treatment for 'expires_at', we are going to take
                # the earliest expiration instead.
                if existing_val != val:
                    LOG.info(_LI('"expires_at" has conflicting values '
                                 '%(existing)s and %(new)s.  Will use the '
                                 'earliest value.'),
                             {'existing': existing_val, 'new': val})
                if existing_val is None or val is None:
                    val = existing_val or val
                else:
                    val = min(existing_val, val)
            elif existing_val != val:
                msg = _('Unable to reconcile identity attribute %(attribute)s '
                        'as it has conflicting values %(new)s and %(old)s') % (
                            {'attribute': key,
                             'new': val,
                             'old': existing_val})
                raise exception.Unauthorized(msg)
        return super(AuthContext, self).__setitem__(key, val)


# TODO(blk-u): this class doesn't use identity_api directly, but makes it
# available for consumers. Consumers should probably not be getting
# identity_api from this since it's available in global registry, then
# identity_api should be removed from this list.
@dependency.requires('identity_api', 'resource_api', 'trust_api')
class AuthInfo(object):
    """Encapsulation of "auth" request."""

    @staticmethod
    def create(context, auth=None):
        auth_info = AuthInfo(context, auth=auth)
        auth_info._validate_and_normalize_auth_data()
        return auth_info

    def __init__(self, context, auth=None):
        self.context = context
        self.auth = auth
        self._scope_data = (None, None, None, None)
        # self._scope_data is (account_id, project_id, trust_ref, unscoped)
        # project scope: (None, project_id, None, None)
        # account scope: (account_id, None, None, None)
        # trust scope: (None, None, trust_ref, None)
        # unscoped: (None, None, None, 'unscoped')

    def _assert_project_is_enabled(self, project_ref):
        # ensure the project is enabled
        try:
            self.resource_api.assert_project_enabled(
                project_id=project_ref['id'],
                project=project_ref)
        except AssertionError as e:
            LOG.warning(six.text_type(e))
            six.reraise(exception.Unauthorized, exception.Unauthorized(e),
                        sys.exc_info()[2])

    def _assert_account_is_enabled(self, account_ref):
        try:
            self.resource_api.assert_account_enabled(
                account_id=account_ref['id'],
                account=account_ref)
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

    def _lookup_project(self, project_info):
        project_id = project_info.get('id')
        project_name = project_info.get('name')
        project_ref = None
        if not project_id and not project_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='project')
        try:
            if project_name:
                if 'account' not in project_info:
                    raise exception.ValidationError(attribute='account',
                                                    target='project')
                account_ref = self._lookup_account(project_info['account'])
                project_ref = self.resource_api.get_project_by_name(
                    project_name, account_ref['id'])
            else:
                project_ref = self.resource_api.get_project(project_id)
                # NOTE(morganfainberg): The _lookup_account method will raise
                # exception.Unauthorized if the account isn't found or is
                # disabled.
                self._lookup_account({'id': project_ref['account_id']})
        except exception.ProjectNotFound as e:
            raise exception.Unauthorized(e)
        self._assert_project_is_enabled(project_ref)
        return project_ref

    def _lookup_trust(self, trust_info):
        trust_id = trust_info.get('id')
        if not trust_id:
            raise exception.ValidationError(attribute='trust_id',
                                            target='trust')
        trust = self.trust_api.get_trust(trust_id)
        if not trust:
            raise exception.TrustNotFound(trust_id=trust_id)
        return trust

    def _validate_and_normalize_scope_data(self):
        """Validate and normalize scope data."""
        if 'scope' not in self.auth:
            return
        if sum(['project' in self.auth['scope'],
                'account' in self.auth['scope'],
                'unscoped' in self.auth['scope'],
                'OS-TRUST:trust' in self.auth['scope']]) != 1:
            raise exception.ValidationError(
                attribute='project, account, OS-TRUST:trust or unscoped',
                target='scope')
        if 'unscoped' in self.auth['scope']:
            self._scope_data = (None, None, None, 'unscoped')
            return
        if 'project' in self.auth['scope']:
            project_ref = self._lookup_project(self.auth['scope']['project'])
            self._scope_data = (None, project_ref['id'], None, None)
        elif 'account' in self.auth['scope']:
            account_ref = self._lookup_account(self.auth['scope']['account'])
            self._scope_data = (account_ref['id'], None, None, None)
        elif 'OS-TRUST:trust' in self.auth['scope']:
            if not CONF.trust.enabled:
                raise exception.Forbidden('Trusts are disabled.')
            trust_ref = self._lookup_trust(
                self.auth['scope']['OS-TRUST:trust'])
            # TODO(ayoung): when trusts support accounts, fill in account data
            if trust_ref.get('project_id') is not None:
                project_ref = self._lookup_project(
                    {'id': trust_ref['project_id']})
                self._scope_data = (None, project_ref['id'], trust_ref, None)
            else:
                self._scope_data = (None, None, trust_ref, None)

    def _validate_auth_methods(self):
        if 'identity' not in self.auth:
            raise exception.ValidationError(attribute='identity',
                                            target='auth')

        # make sure auth methods are provided
        if 'methods' not in self.auth['identity']:
            raise exception.ValidationError(attribute='methods',
                                            target='identity')

        # make sure all the method data/payload are provided
        for method_name in self.get_method_names():
            if method_name not in self.auth['identity']:
                raise exception.ValidationError(attribute=method_name,
                                                target='identity')

        # make sure auth method is supported
        for method_name in self.get_method_names():
            if method_name not in AUTH_METHODS:
                raise exception.AuthMethodNotSupported()

    def _validate_and_normalize_auth_data(self):
        """Make sure "auth" is valid."""
        # make sure "auth" exist
        if not self.auth:
            raise exception.ValidationError(attribute='auth',
                                            target='request body')

        self._validate_auth_methods()
        self._validate_and_normalize_scope_data()

    def get_method_names(self):
        """Returns the identity method names.

        :returns: list of auth method names

        """
        # Sanitizes methods received in request's body
        # Filters out duplicates, while keeping elements' order.
        method_names = []
        for method in self.auth['identity']['methods']:
            if method not in method_names:
                method_names.append(method)
        return method_names

    def get_method_data(self, method):
        """Get the auth method payload.

        :returns: auth method payload

        """
        if method not in self.auth['identity']['methods']:
            raise exception.ValidationError(attribute=method,
                                            target='identity')
        return self.auth['identity'][method]

    def get_scope(self):
        """Get scope information.

        Verify and return the scoping information.

        :returns: (account_id, project_id, trust_ref, unscoped).
                   If scope to a project, (None, project_id, None, None)
                   will be returned.
                   If scoped to a account, (account_id, None, None, None)
                   will be returned.
                   If scoped to a trust, (None, project_id, trust_ref, None),
                   Will be returned, where the project_id comes from the
                   trust definition.
                   If unscoped, (None, None, None, 'unscoped') will be
                   returned.

        """
        return self._scope_data

    def set_scope(self, account_id=None, project_id=None, trust=None,
                  unscoped=None):
        """Set scope information."""
        if account_id and project_id:
            msg = _('Scoping to both account and project is not allowed')
            raise ValueError(msg)
        if account_id and trust:
            msg = _('Scoping to both account and trust is not allowed')
            raise ValueError(msg)
        if project_id and trust:
            msg = _('Scoping to both project and trust is not allowed')
            raise ValueError(msg)
        self._scope_data = (account_id, project_id, trust, unscoped)


@dependency.requires('assignment_api', 'catalog_api', 'identity_api',
                     'resource_api', 'token_provider_api', 'trust_api',
                     'jio_policy_api', 'credential_api')
class Auth(controller.V3Controller):

    # Note(atiwari): From V3 auth controller code we are
    # calling protection() wrappers, so we need to setup
    # the member_name and  collection_name attributes of
    # auth controller code.
    # In the absence of these attributes, default 'entity'
    # string will be used to represent the target which is
    # generic. Policy can be defined using 'entity' but it
    # would not reflect the exact entity that is in context.
    # We are defining collection_name = 'tokens' and
    # member_name = 'token' to facilitate policy decisions.
    collection_name = 'tokens'
    member_name = 'token'

    def __init__(self, *args, **kw):
        super(Auth, self).__init__(*args, **kw)
        config.setup_authentication()

    def authenticate_for_token(self, context, auth=None):
        """Authenticate user and issue a token."""
        include_catalog = 'nocatalog' not in context['query_string']
        # Decrypt password if present
        if 'auth' in  context['environment']['openstack.params'] and\
           'identity' in  context['environment']['openstack.params']['auth'] and\
           'password' in context['environment']['openstack.params']['auth']['identity'] and\
           'user' in context['environment']['openstack.params']['auth']['identity']['password'] and\
           'password' in context['environment']['openstack.params']['auth']['identity']['password']['user']:
            if 'access' in context['environment']['openstack.params']['auth']['identity']['password']['user']:
                password = context['environment']['openstack.params']['auth']['identity']['password']['user']['password']
                access = context['environment']['openstack.params']['auth']['identity']['password']['user']['access']
                password = self.credential_api.decrypt_password_in_context(access, password)
                context['environment']['openstack.params']['auth']['identity']['password']['user']['password'] = password
            else:
                msg = _LW('access key not found')
                raise exception.ValidationError(msg)
        try:
            auth_info = AuthInfo.create(context, auth=auth)
            auth_context = AuthContext(extras={},
                                       method_names=[],
                                       bind={})
            self.authenticate(context, auth_info, auth_context)
            if auth_context.get('access_token_id'):
                auth_info.set_scope(None, auth_context['project_id'], None)
            self._check_and_set_default_scoping(auth_info, auth_context)
            (account_id, project_id, trust, unscoped) = auth_info.get_scope()

            method_names = auth_info.get_method_names()
            if 'token' in method_names:
                expires_at = datetime.utcnow() + timedelta(hours=1)
            else:
                expires_at = auth_context.get('expires_at')
            method_names += auth_context.get('method_names', [])
            # make sure the list is unique
            method_names = list(set(method_names))
            # NOTE(morganfainberg): define this here so it is clear what the
            # argument is during the issue_v3_token provider call.
            metadata_ref = None

            token_audit_id = auth_context.get('audit_id')
            (token_id, token_data) = self.token_provider_api.issue_v3_token(
                auth_context['user_id'], method_names, expires_at, project_id,
                account_id, auth_context, trust, metadata_ref, include_catalog,
                parent_audit_id=token_audit_id)

            # NOTE(wanghong): We consume a trust use only when we are using
            # trusts and have successfully issued a token.
            if trust:
                self.trust_api.consume_use(trust['id'])
            response = self.format_auth_response(token_data, True)
            return render_token_data_response(token_id, response,
                                              created=True)
        except exception.TrustNotFound as e:
            raise exception.Unauthorized(e)

    def _check_and_set_default_scoping(self, auth_info, auth_context):
        (account_id, project_id, trust, unscoped) = auth_info.get_scope()
        if trust:
            project_id = trust['project_id']
        if account_id or project_id or trust:
            # scope is specified
            return

        # Skip scoping when unscoped federated token is being issued
        if federation.IDENTITY_PROVIDER in auth_context:
            return

        # Do not scope if request is for explicitly unscoped token
        if unscoped is not None:
            return

        # fill in default_project_id if it is available
        try:
            user_ref = self.identity_api.get_user(auth_context['user_id'])
        except exception.UserNotFound as e:
            LOG.exception(six.text_type(e))
            raise exception.Unauthorized(e)

        default_project_id = user_ref.get('default_project_id')
        if not default_project_id:
            # User has no default project. He shall get an unscoped token.
            return

        # make sure user's default project is legit before scoping to it
        try:
            default_project_ref = self.resource_api.get_project(
                default_project_id)
            default_project_account_ref = self.resource_api.get_account(
                default_project_ref['account_id'])
            if (default_project_ref.get('enabled', True) and
                    default_project_account_ref.get('enabled', True)):
                if self.assignment_api.get_roles_for_user_and_project(
                        user_ref['id'], default_project_id):
                    auth_info.set_scope(project_id=default_project_id)
                else:
                    msg = _LW("User %(user_id)s doesn't have access to"
                              " default project %(project_id)s. The token"
                              " will be unscoped rather than scoped to the"
                              " project.")
                    LOG.warning(msg,
                                {'user_id': user_ref['id'],
                                 'project_id': default_project_id})
            else:
                msg = _LW("User %(user_id)s's default project %(project_id)s"
                          " is disabled. The token will be unscoped rather"
                          " than scoped to the project.")
                LOG.warning(msg,
                            {'user_id': user_ref['id'],
                             'project_id': default_project_id})
        except (exception.ProjectNotFound, exception.AccountNotFound):
            # default project or default project account doesn't exist,
            # will issue unscoped token instead
            msg = _LW("User %(user_id)s's default project %(project_id)s not"
                      " found. The token will be unscoped rather than"
                      " scoped to the project.")
            LOG.warning(msg, {'user_id': user_ref['id'],
                              'project_id': default_project_id})

    def authenticate(self, context, auth_info, auth_context):
        """Authenticate user."""

        # The 'external' method allows any 'REMOTE_USER' based authentication
        # In some cases the server can set REMOTE_USER as '' instead of
        # dropping it, so this must be filtered out
        if context['environment'].get('REMOTE_USER'):
            try:
                external = get_auth_method('external')
                external.authenticate(context, auth_info, auth_context)
            except exception.AuthMethodNotSupported:
                # This will happen there is no 'external' plugin registered
                # and the container is performing authentication.
                # The 'kerberos'  and 'saml' methods will be used this way.
                # In those cases, it is correct to not register an
                # 'external' plugin;  if there is both an 'external' and a
                # 'kerberos' plugin, it would run the check on identity twice.
                LOG.debug("No 'external' plugin is registered.")
            except exception.Unauthorized:
                # If external fails then continue and attempt to determine
                # user identity using remaining auth methods
                LOG.debug("Authorization failed for 'external' auth method.")

        # need to aggregate the results in case two or more methods
        # are specified
        auth_response = {'methods': []}
        for method_name in auth_info.get_method_names():
            method = get_auth_method(method_name)
            resp = method.authenticate(context,
                                       auth_info.get_method_data(method_name),
                                       auth_context)
            if resp:
                auth_response['methods'].append(method_name)
                auth_response[method_name] = resp

        if auth_response["methods"]:
            # authentication continuation required
            raise exception.AdditionalAuthRequired(auth_response)

        if 'user_id' not in auth_context:
            msg = _('User not found')
            raise exception.Unauthorized(msg)

    def check_token(self, context):
        token_id = context.get('token_id')
        token_data = self.token_provider_api.validate_v3_token(
            token_id)
        # NOTE(morganfainberg): The code in
        # ``keystone.common.wsgi.render_response`` will remove the content
        # body.
        return render_token_data_response(token_id, token_data)

    def revoke_token(self, context):
        token_id = context.get('token_id')
        return self.token_provider_api.revoke_token(token_id)

    def format_auth_response(self, token_data, is_caller_console):
        if token_data is None:
            return

        account_id = token_data["token"]["user"]["account"]["id"]

        if is_caller_console == True:
            account_id = str(account_id)
        else:
            account_id = account_id.rjust(32, '0')

        res =  dict(account_id=account_id,
                        user_id=token_data["token"]["user"]["id"])
        if 'type' in token_data["token"]["user"]:
            res['user_type'] = token_data["token"]["user"]["type"]
        return res


    # REMOVING ROLES CHECK FOR VALIDATE_TOKEN, onlu for mock
    def validate_token(self, context):
        token_id = context.get('token_id')
        include_catalog = 'nocatalog' not in context['query_string']
        token_data = self.token_provider_api.validate_v3_token(
            token_id)
        if not include_catalog and 'catalog' in token_data['token']:
            del token_data['token']['catalog']
        response = self.format_auth_response(token_data, True)
        return render_token_data_response(token_id, response)

    def validate_token_data(self, context):
        token_id = context.get('token_id')
        include_catalog = 'nocatalog' not in context['query_string']
        token_data = self.token_provider_api.validate_v3_token(
            token_id)
        if not include_catalog and 'catalog' in token_data['token']:
            del token_data['token']['catalog']
        return token_data

    def render_response(self,token_data, context):
        token_id = context.get('token_id')
        return render_token_data_response(token_id, token_data)

    def _validate_token_with_action_resource(self, action, resource, user_id,
                                             project_id, is_implicit_allow, context):
        is_authorized = True
        if len(action) != len(resource) or len(is_implicit_allow) != len(resource):
            raise exception.ValidationError(
                    attribute="equal number of actions and resources",
                                            target="authorize call")
        for act, res,imp_allow in zip(action, resource, is_implicit_allow):
            if imp_allow and (imp_allow == 'True' or imp_allow == 'true' or imp_allow == True):
                imp_allow = True
            else:
                imp_allow = False
            is_authorized = is_authorized and self.jio_policy_api.\
                is_user_authorized(user_id, project_id, act, res, imp_allow)

        if not is_authorized:
            raise exception.Forbidden(
                    message='Policy does not allow to perform this action')

        #return self.validate_token(context)

    def validate_token_with_action_resource_get(self, context):
        token_data = self.validate_token_data(context)
        query_string = context.get('query_string', None)
        if not query_string:
            raise exception.ValidationError(attribute="action and resource",
                                            target="query_string")
        action = query_string.pop('action', None)
        if action is None:
            raise exception.ValidationError(attribute="action",
                                            target="query_string")
        resource = query_string.get('resource', None)
        if resource is None:
            raise exception.ValidationError(attribute="resource",
                                            target="query_string")
        is_implicit_allow = query_string.get('implicit_allow', 'False')
        # get user id
        auth_context = self.get_auth_context(context)
        user_id = token_data["token"]["user"]["id"]
        project_id = token_data["token"]["user"]["account"]["id"]
        self._validate_token_with_action_resource(
                    [action], [resource], user_id, project_id, [is_implicit_allow], context)
        response = self.format_auth_response(token_data, False)
        return self.render_response(response,context)

    def validate_cross_account_with_token(self,context, **kwargs):
        token_data = self.validate_token_data(context)
        act_res_list = kwargs.get('action_resource_list', None)
        if act_res_list:
            try:
                action = [item['action'] for item in act_res_list]
                resource = [item['resource'] for item in act_res_list]
                is_implicit_allow = [item.get('implicit_allow','False') for item in act_res_list]
            except KeyError as e:
                raise exception.ValidationError(attribute="action, resource and implicit_allow",
                                            target="body")

            auth_context = self.get_auth_context(context)

            user_id = token_data["token"]["user"]["id"]
            account_id = token_data["token"]["account"]["id"]
            self._validate_cross_account_with_token(
                    user_id, account_id, resource, action, is_implicit_allow, context)
        response = self.format_auth_response(token_data, False)
        return self.render_response(response ,context)

    def create_pre_signed_url(self, context, **kwargs):
        token_data = self.validate_token_data(context)
        try:
            action = kwargs['action']
            resource = kwargs['resource']
        except KeyError as e:
            raise exception.ValidationError(attribute=e,
                                               target="request body")

        # only single values are allowed in action and resource
        if isinstance(action, list) or isinstance(resource, list):
            raise exception.ValidationError(attribute="single value",
                                  target="action and resource")

        # unit is assumed to be second. Default value 7days = 604800 seconds
        duration = int(kwargs.get('duration', CONF.PresignedUrlKey.MaxPresignedUrlKeyExpiryTime))
        if duration < 1 or duration > CONF.PresignedUrlKey.MaxPresignedUrlKeyExpiryTime:
            raise exception.ValidationError(
                        attribute="positive integer which doesn't exceed %s seconds"%CONF.PresignedUrlKey.MaxPresignedUrlKeyExpiryTime,
                                   target="duration")
        LOG.debug('create_pre_signed_url for action: %s, resource: %s, duration: %s', action, resource, duration)

        auth_context = self.get_auth_context(context)
        user_id = token_data["token"]["user"]["id"]
        account_id = token_data["token"]["account"]["id"]

        self._validate_token_with_action_resource(
                            [action], [resource], user_id, account_id, [False], context)
        expires_at = datetime.utcnow() + timedelta(seconds=duration)
        method_names = ['token']
        (token_id, token_data) = self.token_provider_api.issue_v3_token(
            user_id, method_names, expires_at, account_id,
            account_id, auth_context, None, None, None,
            parent_audit_id=None)

        result = {}
        result['token'] = token_id
        result['action'] = action
        result['resource'] = resource
        if 'object_name' in kwargs and kwargs['object_name'] != None:
            result['object_name'] = kwargs['object_name']
        key = CONF.PresignedUrlKey.ActivePresignedUrlKey
        encrypted_result = utils.aes_encrypt(jsonutils.dumps(result), key)
        headers = [('X-Url-Token', encrypted_result)]
        return wsgi.render_response(headers=headers)

    def _validate_cross_account_with_token(self, user_id, user_acc_id,
                                           resource, action, is_implicit_allow, context):

        is_authorized = True
        if len(action) != len(resource) or len(is_implicit_allow) != len(resource):
            raise exception.ValidationError(
                    attribute="equal number of actions and resources",
                                            target="authorize call")
        for act, res,imp_allow in zip(action, resource, is_implicit_allow):
            if imp_allow and (imp_allow == 'True' or imp_allow == 'true' or imp_allow == True):
                imp_allow = True
            else:
                imp_allow = False
            is_authorized = is_authorized and self.jio_policy_api.\
                 is_cross_account_access_auth(user_id, user_acc_id, res, act, imp_allow)

        if not is_authorized:
            raise exception.Forbidden(
                    message='Policy does not allow to perform this action')

    def validate_token_with_action_resource_post(self, context, **kwargs):
        if 'query_string' in context and context['query_string'] != {}:
            msg = _('query parameters not allowed in url')
            raise exception.ValidationError(message=msg)
        token_data = self.validate_token_data(context)
        act_res_list = kwargs.get('action_resource_list', None)
        if act_res_list:
            try:
                action = [item['action'] for item in act_res_list]
                resource = [item['resource'] for item in act_res_list]
                is_implicit_allow = [item.get('implicit_allow','False') for item in act_res_list]
            except KeyError as e:
                raise exception.ValidationError(attribute="action, resource and implicit_allow",
                                                target="body")
            if action == 'deny':
                raise exception.Forbidden(message='Policy does not allow to'
                                              ' perform this action')
            auth_context = self.get_auth_context(context)
            user_id = token_data["token"]["user"]["id"]
            project_id = token_data["token"]["user"]["account"]["id"]
            self._validate_token_with_action_resource(
                    action, resource, user_id, project_id, is_implicit_allow, context)
        response = self.format_auth_response(token_data, False)
        return self.render_response(response,context)

    def validate_url_with_action_resource_post(self, context, **kwargs):
        try:
            encryption_key = CONF.PresignedUrlKey.PassivePresignedUrlKey
            decrypted_string = utils.aes_decrypt(context['headers']['X-Url-Token'], encryption_key)
            if not 'Token' in decrypted_string or not 'Action' in decrypted_string or not 'Resource' in decrypted_string:
                encryption_key = CONF.PresignedUrlKey.ActivePresignedUrlKey
                decrypted_string = utils.aes_decrypt(context['headers']['X-Url-Token'], encryption_key)
        except Exception:
            LOG.warning(_LW('Invalid pre-signed url %(url)s'), {'url' : context['headers']['X-Url-Token']})
            raise exception.ValidationError(attribute="Valid pre-signed url", target="request")

        qstring = jsonutils.loads(decrypted_string)
        try:
            token_id = qstring['token']
            Action   = qstring['action']
            Resource = qstring['resource']
        except KeyError:
                LOG.warning(_LW('Invalid pre-signed url %(url)s'), {'url' : context['headers']['X-Url-Token']})
                raise exception.ValidationError(attribute="Valid pre-signed url",
                                                target="request")

        #Catching all exceptions raised from validate token
        try:
            token_data = self.token_provider_api.validate_v3_token(
                token_id)
        except Exception:
           LOG.warning(_LW('Pre-signed  url token %(token)s not validated'), {'token' : token_id})
           raise exception.Unauthorized()

        act_res_list = kwargs.get('action_resource_list', None)
        if act_res_list:
            try:
                action = act_res_list[0]['action']
                resource = act_res_list[0]['resource']

                if Action != action or Resource != resource:
                    raise exception.ValidationError(attribute="matching action & resource from the presigned url",
                                                target="body")

                if 'object_name' in qstring and qstring['object_name'] is not None and \
                    ('object_name' not in act_res_list[0] or  act_res_list[0]['object_name'] != qstring['object_name']):
                        raise exception.ValidationError(attribute='valid object_name', target="body")

            except KeyError as e:
                raise exception.ValidationError(attribute="action, resource",
                                                target="body")

            auth_context = self.get_auth_context(context)
            user_id = token_data["token"]["user"]["id"]
            project_id = token_data["token"]["user"]["account"]["id"]


            is_authorized = self.jio_policy_api.\
                is_user_authorized(user_id, project_id, action, resource, False)

            if not is_authorized:
                raise exception.Forbidden(
                    message='Policy does not allow to perform this action')
        else:
            raise exception.ValidationError(attribute="action_resource_list",
                                                target="body")

        response = self.format_auth_response(token_data, False)
        return self.render_response(response,context)

    @controller.protected()
    def revocation_list(self, context, auth=None):
        if not CONF.token.revoke_by_id:
            raise exception.Gone()
        tokens = self.token_provider_api.list_revoked_tokens()

        for t in tokens:
            expires = t['expires']
            if not (expires and isinstance(expires, six.text_type)):
                t['expires'] = timeutils.isotime(expires)
        data = {'revoked': tokens}
        json_data = jsonutils.dumps(data)
        signed_text = cms.cms_sign_text(json_data,
                                        CONF.signing.certfile,
                                        CONF.signing.keyfile)

        return {'signed': signed_text}

    def _combine_lists_uniquely(self, a, b):
        # it's most likely that only one of these will be filled so avoid
        # the combination if possible.
        if a and b:
            return {x['id']: x for x in a + b}.values()
        else:
            return a or b

    @controller.protected()
    def get_auth_projects(self, context):
        auth_context = self.get_auth_context(context)

        user_id = auth_context.get('user_id')
        user_refs = []
        if user_id:
            try:
                user_refs = self.assignment_api.list_projects_for_user(user_id)
            except exception.UserNotFound:
                # federated users have an id but they don't link to anything
                pass

        group_ids = auth_context.get('group_ids')
        grp_refs = []
        if group_ids:
            grp_refs = self.assignment_api.list_projects_for_groups(group_ids)

        refs = self._combine_lists_uniquely(user_refs, grp_refs)
        return resource_controllers.ProjectV3.wrap_collection(context, refs)

    @controller.protected()
    def get_auth_accounts(self, context):
        auth_context = self.get_auth_context(context)

        user_id = auth_context.get('user_id')
        user_refs = []
        if user_id:
            try:
                user_refs = self.assignment_api.list_accounts_for_user(user_id)
            except exception.UserNotFound:
                # federated users have an id but they don't link to anything
                pass

        group_ids = auth_context.get('group_ids')
        grp_refs = []
        if group_ids:
            grp_refs = self.assignment_api.list_accounts_for_groups(group_ids)

        refs = self._combine_lists_uniquely(user_refs, grp_refs)
        return resource_controllers.AccountV3.wrap_collection(context, refs)

    @controller.protected()
    def get_auth_catalog(self, context):
        auth_context = self.get_auth_context(context)
        user_id = auth_context.get('user_id')
        project_id = auth_context.get('project_id')

        if not project_id:
            raise exception.Forbidden(
                _('A project-scoped token is required to produce a service '
                  'catalog.'))

        # The V3Controller base methods mostly assume that you're returning
        # either a collection or a single element from a collection, neither of
        # which apply to the catalog. Because this is a special case, this
        # re-implements a tiny bit of work done by the base controller (such as
        # self-referential link building) to avoid overriding or refactoring
        # several private methods.
        return {
            'catalog': self.catalog_api.get_v3_catalog(user_id, project_id),
            'links': {'self': self.base_url(context, path='auth/catalog')}
        }


# FIXME(gyee): not sure if it belongs here or keystone.common. Park it here
# for now.
def render_token_data_response(token_id, token_data, created=False):
    """Render token data HTTP response.

    Stash token ID into the X-Subject-Token header.

    """
    headers = []
    if token_id != None:
        headers = [('X-Subject-Token', token_id)]

    if created:
        status = (201, 'Created')
    else:
        status = (200, 'OK')

    return wsgi.render_response(body=token_data,
                                status=status, headers=headers)
