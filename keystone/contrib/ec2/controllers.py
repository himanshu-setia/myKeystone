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

"""Main entry point into the EC2 Credentials service.

This service allows the creation of access/secret credentials used for
the ec2 interop layer of OpenStack.

A user can create as many access/secret pairs, each of which map to a
specific project.  This is required because OpenStack supports a user
belonging to multiple projects, whereas the signatures created on ec2-style
requests don't allow specification of which project the user wishes to act
upon.

To complete the cycle, we provide a method that OpenStack services can
use to validate a signature and get a corresponding OpenStack token.  This
token allows method calls to other services within the context the
access/secret was created.  As an example, Nova requests Keystone to validate
the signature of a request, receives a token, and then makes a request to
Glance to list images needed to perform the requested task.

"""

import abc
import sys
import uuid
import json

from keystoneclient.contrib.ec2 import utils as ec2_utils
from oslo_serialization import jsonutils
import six
import time
import base64

from oslo_config import cfg
from six.moves import urllib
from keystone.common import controller
from keystone.common import dependency
from keystone.common import utils
from keystone.common import wsgi
from keystone import exception
from keystone.i18n import _
from keystone.models import token_model

CONF = cfg.CONF

@dependency.requires('assignment_api', 'catalog_api', 'credential_api',
                     'identity_api', 'resource_api', 'role_api',
                     'token_provider_api')
@six.add_metaclass(abc.ABCMeta)
class Ec2ControllerCommon(object):
    def check_signature(self, creds_ref, credentials):
        signer = ec2_utils.Ec2Signer(creds_ref['secret'])
        signature = signer.generate(credentials)
        # NOTE(davechen): credentials.get('signature') is not guaranteed to
        # exist, we need check it explicitly.
        if credentials.get('signature'):
            if utils.auth_str_equal(credentials['signature'], signature):
                return True
            # NOTE(vish): Some client libraries don't use the port when signing
            #             requests, so try again without port.
            elif ':' in credentials['host']:
                hostname, _port = credentials['host'].split(':')
                credentials['host'] = hostname
                # NOTE(davechen): we need reinitialize 'signer' to avoid
                # contaminated status of signature, this is similar with
                # other programming language libraries, JAVA for example.
                signer = ec2_utils.Ec2Signer(creds_ref['secret'])
                signature = signer.generate(credentials)
                if utils.auth_str_equal(credentials['signature'],
                                        signature):
                    return True
                raise exception.Unauthorized(
                    message='Invalid JCS signature.')
            else:
                raise exception.Unauthorized(
                    message='Invalid JCS signature.')
        # Raise the exception when credentials.get('signature') is None
        else:
            raise exception.Unauthorized(message='JCS signature not supplied.')

    @abc.abstractmethod
    def authenticate(self, context, credentials=None, ec2Credentials=None):
        """Validate a signed JCS request and provide a token.

        Other services (such as Nova) use this **admin** call to determine
        if a request they signed received is from a valid user.

        If it is a valid signature, an OpenStack token that maps
        to the user/tenant is returned to the caller, along with
        all the other details returned from a normal token validation
        call.

        The returned token is useful for making calls to other
        OpenStack services within the context of the request.

        :param context: standard context
        :param credentials: dict of ec2 signature
        :param ec2Credentials: DEPRECATED dict of ec2 signature
        :returns: token: OpenStack token equivalent to access key along
                         with the corresponding service catalog and roles
        """
        raise exception.NotImplemented()

    def _authenticate(self, context, credentials=None, ec2credentials=None):
        """Common code shared between the V2 and V3 authenticate methods.
        :returns: user_ref, tenant_ref, metadata_ref, roles_ref, catalog_ref
        """
        # FIXME(ja): validate that a service token was used!

        # NOTE(termie): backwards compat hack
        if not credentials and ec2credentials:
            credentials = ec2credentials

        if credentials is None:
            raise exception.Unauthorized(message='JCS credentials not supplied.')

        if 'access' not in credentials:
            raise exception.Unauthorized(message='JCS access key not supplied.')

        creds_ref = self._get_credentials(credentials['access'])
        self._validate_timestamp(credentials)

        self.check_signature(creds_ref, credentials)

        # TODO(termie): don't create new tokens every time
        # TODO(termie): this is copied from TokenController.authenticate
        user_ref = self.identity_api.get_user(creds_ref['user_id'])
        metadata_ref = {}
        if context:
            context['UserInfo'] = {'UserName': user_ref['name'], 'UserType': user_ref['type'], 'UserId': user_ref['id'], 'AccountId': user_ref['account_id']}

        trust_id = creds_ref.get('trust_id')
        if trust_id:
            metadata_ref['trust_id'] = trust_id
            metadata_ref['trustee_user_id'] = user_ref['id']

        # Validate that the auth info is valid and nothing is disabled
        try:
            self.identity_api.assert_user_enabled(
                user_id=user_ref['id'], user=user_ref)
            self.resource_api.assert_account_enabled(
                account_id=user_ref['account_id'])
        except AssertionError as e:
            six.reraise(exception.Unauthorized, exception.Unauthorized(e),
                        sys.exc_info()[2])

        return user_ref, None, metadata_ref, None, None

    def _validate_timestamp(self,credentials):
        """Validate the timestamp for signature
        """
        try:
            if 'params' in credentials:
                timestamp = credentials['params']['Timestamp']
                rcvd_time_gmt = time.strptime(timestamp,"%Y-%m-%dT%H:%M:%SZ")
            else:
                timestamp = base64.urlsafe_b64decode(str(credentials['token'])).split("\n")[3]
                try:
                    rcvd_time_gmt = time.strptime(timestamp,"%a, %d %b %Y %H:%M:%S GMT")
                except ValueError:
                    raise exception.ValidationError(attribute="Correct Timestamp format", target="token")

        except KeyError as e:
            raise exception.ValidationError(attribute=e,
                                            target="credentials")
        curr_time_gmt = time.gmtime()
        diff_time = CONF.AuthTimeMisMatch.Time
        #If the request timestamp is more than the configured time from the current, send 403.
        if time.mktime(curr_time_gmt) - time.mktime(rcvd_time_gmt) > diff_time:
            raise exception.Forbidden(message='Timestamp validation failed')

    def create_credential(self, context, user_id, tenant_id):
        """Create a secret/access pair for use with ec2 style auth.

        Generates a new set of credentials that map the user/tenant
        pair.

        :param context: standard context
        :param user_id: id of user
        :param tenant_id: id of tenant
        :returns: credential: dict of ec2 credential
        """

        self.identity_api.get_user(user_id)
        self.resource_api.get_project(tenant_id)
        trust_id = self._get_trust_id_for_request(context)
        blob = {'access': uuid.uuid4().hex,
                'secret': uuid.uuid4().hex,
                'trust_id': trust_id}
        credential_id = utils.hash_access_key(blob['access'])
        cred_ref = {'user_id': user_id,
                    'project_id': tenant_id,
                    'blob': jsonutils.dumps(blob),
                    'id': credential_id,
                    'type': 'ec2'}
        self.credential_api.create_credential(credential_id, cred_ref)
        return {'credential': self._convert_v3_to_ec2_credential(cred_ref)}

    def get_credentials(self, user_id):
        """List all credentials for a user.

        :param user_id: id of user
        :returns: credentials: list of ec2 credential dicts
        """

        self.identity_api.get_user(user_id)
        credential_refs = self.credential_api.list_credentials_for_user(
            user_id)
        return {'credentials':
                [self._convert_v3_to_ec2_credential(credential)
                    for credential in credential_refs]}

    def get_credential(self, user_id, credential_id):
        """Retrieve a user's access/secret pair by the access key.

        Grab the full access/secret pair for a given access key.

        :param user_id: id of user
        :param credential_id: access key for credentials
        :returns: credential: dict of ec2 credential
        """

        self.identity_api.get_user(user_id)
        return {'credential': self._get_credentials(credential_id)}

    def delete_credential(self, user_id, credential_id):
        """Delete a user's access/secret pair.

        Used to revoke a user's access/secret pair

        :param user_id: id of user
        :param credential_id: access key for credentials
        :returns: bool: success
        """

        self.identity_api.get_user(user_id)
        self._get_credentials(credential_id)
        ec2_credential_id = utils.hash_access_key(credential_id)
        return self.credential_api.delete_credential(ec2_credential_id)

    @staticmethod
    def _convert_v3_to_ec2_credential(credential):
        # Prior to bug #1259584 fix, blob was stored unserialized
        # but it should be stored as a json string for compatibility
        # with the v3 credentials API.  Fall back to the old behavior
        # for backwards compatibility with existing DB contents
        try:
            blob = jsonutils.loads(credential['blob'])
        except TypeError:
            blob = credential['blob']
        return {'user_id': credential.get('user_id'),
                'tenant_id': credential.get('project_id'),
                'access': blob.get('access'),
                'secret': blob.get('secret'),
                'trust_id': blob.get('trust_id')}

    def _get_credentials(self, credential_id):
        """Return credentials from an ID.

        :param credential_id: id of credential
        :raises exception.Unauthorized: when credential id is invalid
        :returns: credential: dict of ec2 credential.
        """
        ec2_credential_id = utils.hash_access_key(credential_id)
        creds = self.credential_api.get_credential(ec2_credential_id)
        if not creds:
            raise exception.Unauthorized(message='JCS access key not found.')
        return self._convert_v3_to_ec2_credential(creds)


@dependency.requires('policy_api', 'token_provider_api', 'jio_policy_api')
class Ec2Controller(Ec2ControllerCommon, controller.V2Controller):

    @controller.v2_deprecated
    def authenticate(self, context, credentials=None, ec2Credentials=None):
        (user_ref, tenant_ref, metadata_ref, roles_ref,
         catalog_ref) = self._authenticate(context, credentials=credentials,
                                           ec2credentials=ec2Credentials)

        # NOTE(morganfainberg): Make sure the data is in correct form since it
        # might be consumed external to Keystone and this is a v2.0 controller.
        # The token provider does not explicitly care about user_ref version
        # in this case, but the data is stored in the token itself and should
        # match the version
        user_ref = self.v3_to_v2_user(user_ref)
        auth_token_data = dict(user=user_ref,
                               tenant=tenant_ref,
                               metadata=metadata_ref,
                               id='placeholder')
        (token_id, token_data) = self.token_provider_api.issue_v2_token(
            auth_token_data, roles_ref, catalog_ref)
        return token_data


    def validate_cross_account_with_sign(self,context, credentials=None, ec2Credentials=None):
        (user_ref, tenant_ref, metadata_ref, roles_ref,
         catalog_ref) = self._authenticate(context, credentials=credentials,
                                           ec2credentials=ec2Credentials)
        user_id = user_ref["id"]
        account_id = user_ref["account_id"]
        query_string = context.get('query_string', None)

        if query_string:
            action = query_string.pop('action', None)
            resource = query_string.pop('resource', None)
            imp_allow = query_string.pop('implicit_allow', False)

            if imp_allow and (imp_allow == 'True' or imp_allow == 'true' or imp_allow == True):
                imp_allow = True
            else:
                imp_allow = False
            if action and resource:
                is_authorized = self.jio_policy_api.\
                    is_cross_account_access_auth(user_id, account_id, resource, action, imp_allow)
                if not is_authorized:
                    raise exception.Forbidden(message='Policy does not allow to'
                                          ' perform this action')
            else:
                raise exception.ValidationError(attribute="action and resource",
                                            target="query_string")
        else:
            act_res_list = None
            if ec2Credentials:
                act_res_list = ec2Credentials.get("action_resource_list", None)
            if not act_res_list and credentials:
                act_res_list = credentials.get("action_resource_list",None)
            if act_res_list:
                try:
                    action = [item['action'] for item in act_res_list]
                    resource = [item['resource'] for item in act_res_list]
                    is_implicit_allow = [item.get('implicit_allow', False) for item in act_res_list]
                except KeyError as e:
                    raise exception.ValidationError(attribute="action and resource",
                                            target="body")
                is_authorized = True
                for act, res, imp_allow in zip(action, resource, is_implicit_allow):
                    if imp_allow and (imp_allow == 'True' or imp_allow == 'true' or imp_allow == True):
                        imp_allow = True
                    else:
                        imp_allow = False
                    is_authorized = is_authorized and self.jio_policy_api.\
                        is_cross_account_access_auth(user_id, account_id, res, act, imp_allow)

                if not is_authorized:
                    raise exception.Forbidden(message='Policy does not allow to'
                                          ' perform this action')


        # NOTE(morganfainberg): Make sure the data is in correct form since it
        # might be consumed external to Keystone and this is a v2.0 controller.
        # The token provider does not explicitly care about user_ref version
        # in this case, but the data is stored in the token itself and should
        # match the version
        user_ref = self.v3_to_v2_user(user_ref)
        auth_token_data = dict(user=user_ref,
                               tenant=tenant_ref,
                               metadata=metadata_ref,
                               id='placeholder')
        (token_id, token_data) = self.token_provider_api.issue_v2_token(
            auth_token_data, roles_ref, catalog_ref)

        account_id = account_id.rjust(32, '0')
        response = dict(account_id=account_id,
                        user_id=user_id,
                        token_id=token_data["access"]["token"]["id"])
        if 'type' in token_data["access"]["user"]:
            response['user_type'] = token_data["access"]["user"]['type']
        return response


    def authorise_with_action_resource(self, context, credentials=None, ec2Credentials=None):
        (user_ref, tenant_ref, metadata_ref, roles_ref,
         catalog_ref) = self._authenticate(context, credentials=credentials,
                                           ec2credentials=ec2Credentials)
        # get user id
        user_id = user_ref["id"]
        project_id = user_ref["account_id"]
        query_string = context.get('query_string', None)
        if query_string:
            action = query_string.pop('action', None)
            resource = query_string.get('resource', None)
            imp_allow = query_string.get('implicit_allow', False)
            if imp_allow and (imp_allow == 'True' or imp_allow == 'true' or imp_allow == True):
                imp_allow = True
            else:
                imp_allow = False
            if action and resource:
                is_authorized = self.jio_policy_api.\
                    is_user_authorized(user_id, project_id, action, resource, imp_allow)
                if not is_authorized:
                    raise exception.Forbidden(message='Policy does not allow to'
                                          ' perform this action')
            else:
                raise exception.ValidationError(attribute="action and resource",
                                            target="query_string")
        else:
            act_res_list = None
            if ec2Credentials:
                act_res_list = ec2Credentials.get("action_resource_list", None)
            if not act_res_list and credentials:
                act_res_list = credentials.get("action_resource_list",None)
            if act_res_list:
                try:
                    action = [item['action'] for item in act_res_list]
                    resource = [item['resource'] for item in act_res_list]
                    is_implicit_allow = [item.get('implicit_allow', False) for item in act_res_list]
                except KeyError as e:
                    raise exception.ValidationError(attribute="action and resource",
                                            target="body")
                is_authorized = True
                for act, res, imp_allow in zip(action, resource, is_implicit_allow):
                    if imp_allow and (imp_allow == 'True' or imp_allow == 'true' or imp_allow == True):
                        imp_allow = True
                    else:
                        imp_allow = False
                    is_authorized = is_authorized and self.jio_policy_api.\
                        is_user_authorized(user_id, project_id, act, res, imp_allow)

                if not is_authorized:
                    raise exception.Forbidden(message='Policy does not allow to'
                                          ' perform this action')
        

        # NOTE(morganfainberg): Make sure the data is in correct form since it
        # might be consumed external to Keystone and this is a v2.0 controller.
        # The token provider does not explicitly care about user_ref version
        # in this case, but the data is stored in the token itself and should
        # match the version
        user_ref = self.v3_to_v2_user(user_ref)
        auth_token_data = dict(user=user_ref,
                               tenant=tenant_ref,
                               metadata=metadata_ref,
                               id='placeholder')
        (token_id, token_data) = self.token_provider_api.issue_v2_token(
            auth_token_data, roles_ref, catalog_ref)

        project_id = project_id.rjust(32, '0')
        response = dict(account_id=project_id,
                        user_id=user_id,
                        token_id=token_data["access"]["token"]["id"])
        if 'type' in token_data["access"]["user"]:
            response['user_type'] = token_data["access"]["user"]['type']
        return response

    @controller.v2_deprecated
    def get_credential(self, context, user_id, credential_id):
        if not self._is_admin(context):
            self._assert_identity(context, user_id)
        return super(Ec2Controller, self).get_credential(user_id,
                                                         credential_id)

    @controller.v2_deprecated
    def get_credentials(self, context, user_id):
        if not self._is_admin(context):
            self._assert_identity(context, user_id)
        return super(Ec2Controller, self).get_credentials(user_id)

    @controller.v2_deprecated
    def create_credential(self, context, user_id, tenant_id):
        if not self._is_admin(context):
            self._assert_identity(context, user_id)
        return super(Ec2Controller, self).create_credential(context, user_id,
                                                            tenant_id)

    @controller.v2_deprecated
    def delete_credential(self, context, user_id, credential_id):
        if not self._is_admin(context):
            self._assert_identity(context, user_id)
            self._assert_owner(user_id, credential_id)
        return super(Ec2Controller, self).delete_credential(user_id,
                                                            credential_id)

    def _assert_identity(self, context, user_id):
        """Check that the provided token belongs to the user.

        :param context: standard context
        :param user_id: id of user
        :raises exception.Forbidden: when token is invalid

        """
        try:
            token_data = self.token_provider_api.validate_token(
                context['token_id'])
        except exception.TokenNotFound as e:
            raise exception.Unauthorized(e)

        token_ref = token_model.KeystoneToken(token_id=context['token_id'],
                                              token_data=token_data)

        if token_ref.user_id != user_id:
            raise exception.Forbidden(_('Token belongs to another user'))

    def _is_admin(self, context):
        """Wrap admin assertion error return statement.

        :param context: standard context
        :returns: bool: success

        """
        try:
            # NOTE(morganfainberg): policy_api is required for assert_admin
            # to properly perform policy enforcement.
            self.assert_admin(context)
            return True
        except exception.Forbidden:
            return False

    def _assert_owner(self, user_id, credential_id):
        """Ensure the provided user owns the credential.

        :param user_id: expected credential owner
        :param credential_id: id of credential object
        :raises exception.Forbidden: on failure

        """
        ec2_credential_id = utils.hash_access_key(credential_id)
        cred_ref = self.credential_api.get_credential(ec2_credential_id)
        if user_id != cred_ref['user_id']:
            raise exception.Forbidden(_('Credential belongs to another user'))


@dependency.requires('policy_api', 'token_provider_api', 'jio_policy_api')
class Ec2ControllerV3(Ec2ControllerCommon, controller.V3Controller):

    collection_name = 'credentials'
    member_name = 'credential'

    def __init__(self):
        super(Ec2ControllerV3, self).__init__()

    def _check_credential_owner_and_user_id_match(self, context, prep_info,
                                                  user_id, credential_id):
        # NOTE(morganfainberg): this method needs to capture the arguments of
        # the method that is decorated with @controller.protected() (with
        # exception of the first argument ('context') since the protected
        # method passes in *args, **kwargs. In this case, it is easier to see
        # the expected input if the argspec is `user_id` and `credential_id`
        # explicitly (matching the :class:`.ec2_delete_credential()` method
        # below).
        ref = {}
        credential_id = utils.hash_access_key(credential_id)
        ref['credential'] = self.credential_api.get_credential(credential_id)
        # NOTE(morganfainberg): policy_api is required for this
        # check_protection to properly be able to perform policy enforcement.
        self.check_protection(context, prep_info, ref)

    def authenticate(self, context, credentials=None, ec2Credentials=None):
        (user_ref, project_ref, metadata_ref, roles_ref,
         catalog_ref) = self._authenticate(context, credentials=credentials,
                                           ec2credentials=ec2Credentials)

        method_names = ['ec2credential']

        token_id, token_data = self.token_provider_api.issue_v3_token(
            user_ref['id'], method_names, project_id=project_ref['id'],
            metadata_ref=metadata_ref)
        return render_token_data_response(token_id, token_data)

    def validate_cross_account_with_sign(self,context, credentials=None, ec2Credentials=None):
        (user_ref, project_ref, metadata_ref, roles_ref,
         catalog_ref) = self._authenticate(context, credentials=credentials,
                                           ec2credentials=ec2Credentials)
        user_id = user_ref["id"]
        account_id = user_ref["account_id"]
        query_string = context.get('query_string', None)

        if query_string:
            action = query_string.pop('action', None)
            resource = query_string.pop('resource', None)
            imp_allow = query_string.pop('implicit_allow', False)

            if imp_allow and (imp_allow == 'True' or imp_allow == 'true' or imp_allow == True):
                imp_allow = True
            else:
                imp_allow = False
            if action and resource:
                is_authorized = self.jio_policy_api.\
                    is_cross_account_access_auth(user_id, account_id, resource, action, imp_allow)
                if not is_authorized:
                    raise exception.Forbidden(message='Policy does not allow to'
                                          ' perform this action')
            else:
                raise exception.ValidationError(attribute="action and resource",
                                            target="query_string")
        else:
            act_res_list = None
            if ec2Credentials:
                act_res_list = ec2Credentials.get("action_resource_list", None)
                res_acc_id = ec2Credentials.get('res_acc_id', False)
            if not act_res_list and credentials:
                act_res_list = credentials.get("action_resource_list",None)
                res_acc_id = credentials.get('res_acc_id', False)
            if act_res_list:
                try:
                    action = [item['action'] for item in act_res_list]
                    resource = [item['resource'] for item in act_res_list]
                    is_implicit_allow = [item.get('implicit_allow', False) for item in act_res_list]
                except KeyError as e:
                    raise exception.ValidationError(attribute="action and resource",
                                            target="body")
                is_authorized = True
                for act, res, imp_allow in zip(action, resource, is_implicit_allow):
                    if imp_allow and (imp_allow == 'True' or imp_allow == 'true' or imp_allow == True):
                        imp_allow = True
                    else:
                        imp_allow = False
                    is_authorized = is_authorized and self.jio_policy_api.\
                        is_cross_account_access_auth(user_id, account_id, res, act, imp_allow)

                if not is_authorized:
                     raise exception.Forbidden(message='Policy does not allow to'
                                          ' perform this action')

        method_names = ['ec2credential']

        token_id, token_data = self.token_provider_api.issue_v3_token(
            user_id, method_names, project_id=account_id,
            metadata_ref='')

        account_id = account_id.rjust(32, '0')
        response = dict(account_id=account_id,
                        user_id=user_id,
                        token_id=token_id)

        return render_token_data_response(token_id,response)

    def authorise_with_action_resource(self, context, credentials=None, ec2Credentials=None):
        (user_ref, project_ref, metadata_ref, roles_ref,
         catalog_ref) = self._authenticate(context,credentials=credentials,
                                           ec2credentials=ec2Credentials)


        # get user id
        user_id = user_ref["id"]
        project_id = user_ref["account_id"]
        query_string = context.get('query_string', None)
        if query_string:
            action = query_string.pop('action', None)
            resource = query_string.get('resource', None)
            imp_allow = query_string.get('implicit_allow', False)
            if imp_allow and (imp_allow == 'True' or imp_allow == 'true' or imp_allow == True):
                imp_allow = True
            else:
                imp_allow = False
            if action and resource:
                is_authorized = self.jio_policy_api.\
                    is_user_authorized(user_id, project_id, action, resource, imp_allow)
                if not is_authorized:
                    raise exception.Forbidden(message='Policy does not allow to'
                                          ' perform this action')
            else:
                raise exception.ValidationError(attribute="action and resource",
                                            target="query_string")
        else:
            act_res_list = None
            if ec2Credentials:
                act_res_list = ec2Credentials.get("action_resource_list", None)
            if not act_res_list and credentials:
                act_res_list = credentials.get("action_resource_list",None)
            if act_res_list:
                try:
                    action = [item['action'] for item in act_res_list]
                    resource = [item['resource'] for item in act_res_list]
                    is_implicit_allow = [item.get('implicit_allow', False) for item in act_res_list]
                except KeyError as e:
                    raise exception.ValidationError(attribute="action and resource",
                                            target="body")
                is_authorized = True
                for act, res, imp_allow in zip(action, resource, is_implicit_allow):
                    if imp_allow and (imp_allow == 'True' or imp_allow == 'true' or imp_allow == True):
                        imp_allow = True
                    else:
                        imp_allow = False
                    is_authorized = is_authorized and self.jio_policy_api.\
                        is_user_authorized(user_id, project_id, act, res, imp_allow)

                if not is_authorized:
                    raise exception.Forbidden(message='Policy does not allow to'
                                          ' perform this action')

        method_names = ['ec2credential']

        token_id, token_data = self.token_provider_api.issue_v3_token(
            user_id, method_names, project_id=project_id,
            metadata_ref=metadata_ref)

        project_id = project_id.rjust(32, '0')
        response = dict(account_id=project_id,
                        user_id=user_id,
                        token_id=token_id)

        return render_token_data_response(token_id,response)


    @controller.protected(callback=_check_credential_owner_and_user_id_match)
    def ec2_get_credential(self, context, user_id, credential_id):
        ref = super(Ec2ControllerV3, self).get_credential(user_id,
                                                          credential_id)
        return Ec2ControllerV3.wrap_member(context, ref['credential'])

    @controller.protected()
    def ec2_list_credentials(self, context, user_id):
        refs = super(Ec2ControllerV3, self).get_credentials(user_id)
        return Ec2ControllerV3.wrap_collection(context, refs['credentials'])

    @controller.protected()
    def ec2_create_credential(self, context, user_id, tenant_id):
        ref = super(Ec2ControllerV3, self).create_credential(context, user_id,
                                                             tenant_id)
        return Ec2ControllerV3.wrap_member(context, ref['credential'])

    @controller.protected(callback=_check_credential_owner_and_user_id_match)
    def ec2_delete_credential(self, context, user_id, credential_id):
        return super(Ec2ControllerV3, self).delete_credential(user_id,
                                                              credential_id)

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        path = '/users/%(user_id)s/credentials/OS-EC2/%(credential_id)s'
        url = cls.base_url(context, path) % {
            'user_id': ref['user_id'],
            'credential_id': ref['access']}
        ref.setdefault('links', {})
        ref['links']['self'] = url


def render_token_data_response(token_id, token_data):
    """Render token data HTTP response.

    Stash token ID into the X-Subject-Token header.

    """
    headers = [('X-Subject-Token', token_id)]

    return wsgi.render_response(body=token_data,
                                status=(200, 'OK'), headers=headers)
