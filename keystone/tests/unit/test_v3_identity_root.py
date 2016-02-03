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

import logging
import uuid

import fixtures
from oslo_config import cfg
from testtools import matchers

from keystone.common import controller
from keystone import exception
from keystone.tests import unit as tests
from keystone.tests.unit import test_v3


CONF = cfg.CONF


class IdentityTestCase(test_v3.RestfulTestCase):
    """Test users and groups."""

    def setUp(self):
        super(IdentityTestCase, self).setUp()

        self.group = self.new_group_ref(
            account_id=self.account_id)
        self.group = self.identity_api.create_group(self.group)
        self.group_id = self.group['id']

        self.credential_id = uuid.uuid4().hex
        self.credential = self.new_credential_ref(
            user_id=self.user['id'],
            project_id=self.project_id)
        self.credential['id'] = self.credential_id
        self.credential_api.create_credential(
            self.credential_id,
            self.credential)

    # user crud tests

    def test_create_user(self):
        ref = self.new_user_ref(account_id=self.account_id)
        user = '/?Action=CreateUser' + '&Name=' + ref['name'] + \
               '&Description=' + ref['description'] + '&Password='+ \
               ref['password']+'&Email='+ ref['email'] + '&AccountId=' + ref['account_id'] 
        r = self.get(user)
        return self.assertValidUserResponse(r, ref)

    def test_create_user_400(self):
        self.get('/?Action=CreateUser', expected_status=400)

    def test_list_users(self):
        resource_url = '/?Action=ListUsers'
        r = self.get(resource_url)
        self.assertValidUserListResponse(r, ref=self.user,
                                         resource_url=resource_url)

    def test_list_users_with_static_admin_token_and_multiple_backends(self):
        # account-specific operations with the bootstrap ADMIN token is
        # disallowed when account-specific drivers are enabled
        self.config_fixture.config(group='identity',
                                   account_specific_drivers_enabled=True)
        self.get('/?Action=ListUsers', token=CONF.admin_token,
                 expected_status=exception.Unauthorized.code)

    def test_list_users_no_default_project(self):
        user = self.new_user_ref(self.account_id)
        user = self.identity_api.create_user(user)
        resource_url = '/?Action=ListUsers'
        r = self.get(resource_url)
        self.assertValidUserListResponse(r, ref=user,
                                         resource_url=resource_url)

    def test_get_user(self):
        ref = '/?Action=GetUser' + '&Id=' + self.user['id']
        r = self.get(ref)
        self.assertValidUserResponse(r, self.user)

    def test_get_user_with_default_project(self):
        user = self.new_user_ref(account_id=self.account_id,
                                 project_id=self.project_id)
        user = self.identity_api.create_user(user)
        ref = '/?Action=GetUser' + '&Id=' + user['id']
        r = self.get(ref)
        self.assertValidUserResponse(r, user)

    def test_add_user_to_group(self):
        ref= '/?Action=AssignUserToGroup' + '&GroupId=' + self.group_id + '&UserId=' + self.user['id']
        self.get(ref,expected_status=204)

    def test_list_groups_for_user(self):
        # Administrator is allowed to list others' groups
        ref= '/?Action=AssignUserToGroup' + '&GroupId=' + self.group_id + '&UserId=' + self.user['id']
        self.get(ref,expected_status=204)
	
        resource_url = '/?Action=ListGroupsForUser&Id=' + self.user['id']
        r = self.get(resource_url)
        self.assertValidGroupListResponse(r, ref=self.group,
                                          resource_url=resource_url)

    def test_check_user_in_group(self):
        ref= '/?Action=AssignUserToGroup' + '&GroupId=' + self.group_id + '&UserId=' + self.user['id']
        self.get(ref,expected_status=204)

        ref= '/?Action=CheckUserInGroup' + '&GroupId=' + self.group_id + '&UserId=' + self.user['id']
        self.get(ref,expected_status=204)

    def test_list_users_in_group(self):
        ref= '/?Action=AssignUserToGroup' + '&GroupId=' + self.group_id + '&UserId=' + self.user['id']
        self.get(ref,expected_status=204)
        resource_url= '/?Action=ListUserInGroup' + '&Id=' + self.group_id
        r = self.get(resource_url)
        self.assertValidUserListResponse(r, ref=self.user,
                                         resource_url=resource_url)

    def test_remove_user_from_group(self):
        ref= '/?Action=AssignUserToGroup' + '&GroupId=' + self.group_id + '&UserId=' + self.user['id']
        self.get(ref,expected_status=204)
        ref= '/?Action=RemoveUserFromGroup' + '&GroupId=' + self.group_id + '&UserId=' + self.user['id']
        self.get(ref,expected_status=204)

    def test_update_user(self):
        ref = self.new_user_ref(account_id=self.account_id)
        del ref['id']
        user = '/?Action=UpdateUser' + '&Name=' + ref['name'] + \
               '&Id=' + self.user['id'] + '&Description=' + ref['description'] + \
               '&Email='+ ref['email'] + '&AccountId=' + ref['account_id']
        r = self.get(user)
        self.assertValidUserResponse(r, ref)

    def test_delete_user(self):
        # First check the credential for this user is present
        r = self.credential_api.get_credential(self.credential['id'])
        self.assertDictEqual(r, self.credential)
        # Create a second credential with a different user
        self.user2 = self.new_user_ref(
            account_id=self.account['id'],
            project_id=self.project['id'])
        self.user2 = self.identity_api.create_user(self.user2)
        self.credential2 = self.new_credential_ref(
            user_id=self.user2['id'],
            project_id=self.project['id'])
        self.credential_api.create_credential(
            self.credential2['id'],
            self.credential2)
        # Create a token for this user which we can check later
        # gets deleted
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        token = self.get_requested_token(auth_data)
        # Confirm token is valid for now
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=200)

        # Now delete the user
        user = '/?Action=DeleteUser' + '&Id=' + self.user['id']
        self.get(user, expected_status=204)

        # Deleting the user should have deleted any credentials
        # that reference this project
        self.assertRaises(exception.CredentialNotFound,
                          self.credential_api.get_credential,
                          self.credential['id'])
        # And the no tokens we remain valid
        tokens = self.token_provider_api._persistence._list_tokens(
            self.user['id'])
        self.assertEqual(0, len(tokens))
        # But the credential for user2 is unaffected
        r = self.credential_api.get_credential(self.credential2['id'])
        self.assertDictEqual(r, self.credential2)

    # group crud tests

    def test_create_group(self):
        ref = self.new_group_ref(account_id=self.account_id)
        group = '/?Action=CreateGroup' + '&Name=' + ref['name'] + '&Description=' + \
                ref['description'] +'&AccountId=' + ref['account_id'] 
        self.get(group, expected_status=200)
    
    def test_create_group_400(self):
        self.get('/?Action=CreateGroup', expected_status=400)

        self.delete('/groups/%(group_id)s' % {
            'group_id': self.group_id})

    def test_list_groups(self):
        resource_url = '/?Action=ListGroups'
        r = self.get(resource_url)
        self.assertValidGroupListResponse(r, ref=self.group,
                                          resource_url=resource_url)

    def test_get_group(self):
        ref = '/?Action=GetGroup' + '&Id=' + self.group_id
        r = self.get(ref)
        self.assertValidGroupResponse(r, self.group)

    def test_update_group(self):
        ref = self.new_group_ref(account_id=self.account_id)
        del ref['id']
        group = '/?Action=UpdateGroup' + '&Name=' + ref['name'] + '&Id=' + self.group_id + '&Description=' + ref['description']
        r = self.get(group)
        print r
        self.assertValidGroupResponse(r, ref)

    def test_delete_group(self):
        group = '/?Action=DeleteGroup' + '&Id=' + self.group_id
        self.get(group,expected_status=204)
