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

import hashlib
import uuid

from oslo_serialization import jsonutils

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone.common import utils
from keystone.credential import schema
from keystone import exception
from keystone.i18n import _


@dependency.requires('credential_api','identity_api')
class CredentialV3(controller.V3Controller):
    collection_name = 'credentials'
    member_name = 'credential'

    def __init__(self):
        super(CredentialV3, self).__init__()
        self.get_member_from_driver = self.credential_api.get_credential

    def _assign_unique_id(self, ref, trust_id=None):
        # Generates and assigns a unique identifier to
        # a credential reference.
        if ref.get('type', '').lower() == 'ec2':
            try:
                blob = jsonutils.loads(ref.get('blob'))
            except (ValueError, TypeError):
                raise exception.ValidationError(
                    message=_('Invalid blob in credential'))
            if not blob or not isinstance(blob, dict):
                raise exception.ValidationError(attribute='blob',
                                                target='credential')
            if blob.get('access') is None:
                raise exception.ValidationError(attribute='access',
                                                target='blob')
            ret_ref = ref.copy()
            ret_ref['id'] = hashlib.sha256(blob['access']).hexdigest()
            # Update the blob with the trust_id, so credentials created
            # with a trust scoped token will result in trust scoped
            # tokens when authentication via ec2tokens happens
            if trust_id is not None:
                blob['trust_id'] = trust_id
                ret_ref['blob'] = jsonutils.dumps(blob)
            return ret_ref
        else:
            return super(CredentialV3, self)._assign_unique_id(ref)
    
    @staticmethod
    def _improve_response(ref):
        ref.pop('project_id')
        ref.pop('type')

    def _get_credentials_count(self, user_id):
        """Get number of credentials for a user.

        :param user_id: id of user
        :returns: credentials: number of ec2 credential for the given user
        """
        self.identity_api.get_user(user_id)
        credential_refs = self.credential_api.list_credentials_for_user(
            user_id)
        return len(credential_refs)

    @controller.jio_policy_filterprotected(args='Credential')
    @validation.validated(schema.credential_create, 'credential')
    def create_credential(self, context, credential):
        if 'user_id' not in credential:
            user_id = context["environment"]["KEYSTONE_AUTH_CONTEXT"]["user_id"]
            account_id = context["environment"]["KEYSTONE_AUTH_CONTEXT"]["account_id"]
        else:
            user_id = credential['user_id']
            user_ref = self.identity_api.get_user(user_id)
            account_id = user_ref['account_id']
        count = self._get_credentials_count(user_id)
        if count >= 2:
            e = "Not allowed to create more than two access-secret pairs."
            raise exception.Forbidden(message=e)

        blob = {'access': uuid.uuid4().hex,
                'secret': uuid.uuid4().hex }
        credential_id = utils.hash_access_key(blob['access'])
        cred_ref = {'user_id': user_id,
                    'project_id': account_id,
                    'blob': jsonutils.dumps(blob),
                    'id': credential_id,
                    'type': 'ec2'}

        self.credential_api.create_credential(credential_id, cred_ref)
        self._improve_response(cred_ref)
        return cred_ref


    @staticmethod
    def _blob_to_json(ref):
        # credentials stored via ec2tokens before the fix for #1259584
        # need json serializing, as that's the documented API format
        if ref.get('type', '').lower() == 'ec2':
            try:
                blob = jsonutils.loads(ref.get('blob'))
            except (ValueError, TypeError):
                raise exception.ValidationError(
                message=_('Invalid blob in credential'))
            if not blob or not isinstance(blob, dict):
                raise exception.ValidationError(attribute='blob',
                            target='credential')
            new_ref = ref.copy()
            blob.pop('secret')
            new_ref['blob'] = blob
            return new_ref
        else:
            return ref

    @controller.jio_policy_filterprotected(args='Credential',filters=['UserId'])
    def list_credentials(self, context, filters):
        hints = CredentialV3.build_driver_hints(context, filters)
        refs = self.credential_api.list_credentials(hints)
        ret_refs = [self._blob_to_json(r) for r in refs]
        for ref in ret_refs:
            self._improve_response(ref)
        return CredentialV3.wrap_collection(context, ret_refs,
                                            hints=hints)

    @controller.jio_policy_filterprotected(args='Credential')
    def get_user_credentials(self, context, user_id):
        if user_id is None:
            raise exception.ValidationError(attribute='userId is none',
                            target='User_d')
        refs = self.credential_api.list_credentials_for_user(
                     user_id)
        ret_refs = [self._blob_to_json(r) for r in refs]
        for ref in ret_refs:
            self._improve_response(ref)
        return CredentialV3.wrap_collection(context, ret_refs)

    @controller.jio_policy_user_filterprotected(args='Credential')
    def get_credential(self, context, credential_id):
        ref = self.credential_api.get_credential(credential_id)
        ret_ref = self._blob_to_json(ref)
        self._improve_response(ref)
        return CredentialV3.wrap_member(context, ret_ref)

    @controller.jio_policy_user_filterprotected(args='Credential')
    def delete_credential(self, context, credential_id):
        return self.credential_api.delete_credential(credential_id)
