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
import json
import uuid

from keystoneclient.contrib.ec2 import utils as ec2_utils
from oslo_config import cfg
from testtools import matchers

from keystone import exception
from keystone.tests.unit import test_v3


CONF = cfg.CONF


class CredentialBaseTestCase(test_v3.RestfulTestCase):
    def _create_dict_blob_credential(self):
        blob = {"access": uuid.uuid4().hex,
                "secret": uuid.uuid4().hex}
        credential_id = hashlib.sha256(blob['access']).hexdigest()
        credential = self.new_credential_ref(
            user_id=self.user['id'],
            project_id=self.project_id)
        credential['id'] = credential_id

        # Store the blob as a dict *not* JSON ref bug #1259584
        # This means we can test the dict->json workaround, added
        # as part of the bugfix for backwards compatibility works.
        credential['blob'] = blob
        credential['type'] = 'ec2'
        # Create direct via the DB API to avoid validation failure
        r = self.credential_api.create_credential(
            credential_id,
            credential)
        expected_blob = json.dumps(blob)
        return expected_blob, credential_id


class CredentialTestCase(CredentialBaseTestCase):
    """Test credential CRUD."""
    def setUp(self):

        super(CredentialTestCase, self).setUp()

        self.credential_id = uuid.uuid4().hex
        self.credential = self.new_credential_ref(
            user_id=self.user['id'],
            project_id=self.project_id)
        self.credential['id'] = self.credential_id
        self.credential_api.create_credential(
            self.credential_id,
            self.credential)

    def test_credential_api_delete_credentials_for_project(self):
        self.credential_api.delete_credentials_for_project(self.project_id)
        # Test that the credential that we created in .setUp no longer exists
        # once we delete all credentials for self.project_id
        self.assertRaises(exception.CredentialNotFound,
                          self.credential_api.get_credential,
                          credential_id=self.credential_id)

    def test_credential_api_delete_credentials_for_user(self):
        self.credential_api.delete_credentials_for_user(self.user_id)
        # Test that the credential that we created in .setUp no longer exists
        # once we delete all credentials for self.user_id
        self.assertRaises(exception.CredentialNotFound,
                          self.credential_api.get_credential,
                          credential_id=self.credential_id)

    def test_list_credentials(self):
        """Call ``GET /credentials``."""
        r = self.get('/?Action=ListCredentials')
        self.assertValidCredentialListResponse(r, ref=self.credential)

    def test_create_credential(self):
        """Call ``POST /credentials``."""
        ref = self.new_credential_ref(user_id=self.user['id'])
        cred = '/?Action=CreateCredential' + '&Blob=' + ref['blob'] + '&UserId=' + ref['user_id'] + '&Type=' + ref['type']
        r = self.get(cred)
        self.assertValidCredentialResponse(r, ref)

    def test_get_credential(self):
        """Call ``GET /credentials/{credential_id}``."""
        cred = '/?Action=GetCredential' + '&Id=' + self.credential_id
        r = self.get(cred)
        self.assertValidCredentialResponse(r, self.credential)

    def test_delete_credential(self):
        """Call ``DELETE /credentials/{credential_id}``."""
        cred = '/?Action=DeleteCredential' + '&Id=' + self.credential_id
        self.get(cred, expected_status=204)

    def test_create_ec2_credential(self):
        """Call ``POST /credentials`` for creating ec2 credential."""
        ref = self.new_credential_ref(user_id=self.user['id'],
                                      project_id=self.project_id)
        blob = {"access": uuid.uuid4().hex,
                "secret": uuid.uuid4().hex}
        ref['blob'] = json.dumps(blob)
        ref['type'] = 'ec2'

        cred = '/?Action=CreateCredential' + '&Blob=' + ref['blob'] + '&UserId=' + ref['user_id'] + '&Type=' + ref['type'] + '&ProjectId=' + ref['project_id']

        r = self.get(cred)
        self.assertValidCredentialResponse(r, ref)
        # Assert credential id is same as hash of access key id for
        # ec2 credentials
        self.assertEqual(r.result['credential']['id'],
                         hashlib.sha256(blob['access']).hexdigest())
        # Create second ec2 credential with the same access key id and check
        # for conflict.
        self.get(cred, expected_status=409)

    def test_get_ec2_dict_blob(self):
        """Ensure non-JSON blob data is correctly converted."""
        expected_blob, credential_id = self._create_dict_blob_credential()

        cred = '/?Action=GetCredential' + '&Id=' + credential_id
        r = self.get(cred)
        self.assertEqual(expected_blob, r.result['credential']['blob'])

    def test_list_ec2_dict_blob(self):
        """Ensure non-JSON blob data is correctly converted."""
        expected_blob, credential_id = self._create_dict_blob_credential()

        list_r =self.get('/?Action=ListCredentials')
        list_creds = list_r.result['credentials']
        list_ids = [r['id'] for r in list_creds]
        self.assertIn(credential_id, list_ids)
        for r in list_creds:
            if r['id'] == credential_id:
                self.assertEqual(expected_blob, r['blob'])

    def test_create_non_ec2_credential(self):
        """Call ``POST /credentials`` for creating non-ec2 credential."""
        ref = self.new_credential_ref(user_id=self.user['id'])
        blob = {"access": uuid.uuid4().hex,
                "secret": uuid.uuid4().hex}
        ref['blob'] = json.dumps(blob)
        cred = '/?Action=CreateCredential' + '&Blob=' + ref['blob'] + '&UserId=' + ref['user_id'] + '&Type=' + ref['type']

        r = self.get(cred)
        self.assertValidCredentialResponse(r, ref)
        # Assert credential id is not same as hash of access key id for
        # non-ec2 credentials
        self.assertNotEqual(r.result['credential']['id'],
                            hashlib.sha256(blob['access']).hexdigest())

    #def test_create_ec2_credential_with_missing_project_id(self):
        #"""Call ``POST /credentials`` for creating ec2
        #   credential with missing project_id.
        #"""
        #ref = self.new_credential_ref(user_id=self.user['id'])
        #blob = {"access": uuid.uuid4().hex,
        #        "secret": uuid.uuid4().hex}
        #ref['blob'] = json.dumps(blob)
        #ref['type'] = 'ec2'
        #cred = '/?Action=CreateCredential' + '&Blob=' + ref['blob'] + '&UserId=' + ref['user_id'] #+ '&Type=' + ref['type']
        # Assert 400 status for bad request with missing project_id
        #self.get(cred, expected_status=400)

    def test_create_ec2_credential_with_invalid_blob(self):
        """Call ``POST /credentials`` for creating ec2
           credential with invalid blob.
        """
        ref = self.new_credential_ref(user_id=self.user['id'],
                                      project_id=self.project_id)
        ref['blob'] = '{"abc":"def"d}'
        ref['type'] = 'ec2'
        cred = '/?Action=CreateCredential' + '&Blob=' + ref['blob'] + '&UserId=' + ref['user_id'] + '&Type=' + ref['type'] + '&ProjectId=' + ref['project_id']
        # Assert 400 status for bad request containing invalid
        # blob
        response = self.get(cred, expected_status=400)
