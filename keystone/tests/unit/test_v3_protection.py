# Copyright 2012 OpenStack Foundation
# Copyright 2013 IBM Corp.
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

import uuid

from oslo_config import cfg
from oslo_serialization import jsonutils

from keystone import exception
from keystone.policy.backends import rules
from keystone.tests import unit as tests
from keystone.tests.unit.ksfixtures import temporaryfile
from keystone.tests.unit import test_v3


CONF = cfg.CONF
DEFAULT_ACCOUNT_ID = CONF.identity.default_account_id


class IdentityTestProtectedCase(test_v3.RestfulTestCase):
    """Test policy enforcement on the v3 Identity API."""

    def setUp(self):
        """Setup for Identity Protection Test Cases.

        As well as the usual housekeeping, create a set of accounts,
        users, roles and projects for the subsequent tests:

        - Three accounts: A,B & C.  C is disabled.
        - AccountA has user1, AccountB has user2 and user3
        - AccountA has group1 and group2, AccountB has group3
        - User1 has two roles on AccountA
        - User2 has one role on AccountA

        Remember that there will also be a fourth account in existence,
        the default account.

        """
        # Ensure that test_v3.RestfulTestCase doesn't load its own
        # sample data, which would make checking the results of our
        # tests harder
        super(IdentityTestProtectedCase, self).setUp()
        self.tempfile = self.useFixture(temporaryfile.SecureTempFile())
        self.tmpfilename = self.tempfile.file_name
        self.config_fixture.config(group='oslo_policy',
                                   policy_file=self.tmpfilename)

        # A default auth request we can use - un-scoped user token
        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'])

    def load_sample_data(self):
        self._populate_default_account()
        # Start by creating a couple of accounts
        self.accountA = self.new_account_ref()
        self.resource_api.create_account(self.accountA['id'], self.accountA)
        self.accountB = self.new_account_ref()
        self.resource_api.create_account(self.accountB['id'], self.accountB)
        self.accountC = self.new_account_ref()
        self.accountC['enabled'] = False
        self.resource_api.create_account(self.accountC['id'], self.accountC)

        # Now create some users, one in accountA and two of them in accountB
        self.user1 = self.new_user_ref(account_id=self.accountA['id'])
        password = uuid.uuid4().hex
        self.user1['password'] = password
        self.user1 = self.identity_api.create_user(self.user1)
        self.user1['password'] = password

        self.user2 = self.new_user_ref(account_id=self.accountB['id'])
        password = uuid.uuid4().hex
        self.user2['password'] = password
        self.user2 = self.identity_api.create_user(self.user2)
        self.user2['password'] = password

        self.user3 = self.new_user_ref(account_id=self.accountB['id'])
        password = uuid.uuid4().hex
        self.user3['password'] = password
        self.user3 = self.identity_api.create_user(self.user3)
        self.user3['password'] = password

        self.group1 = self.new_group_ref(account_id=self.accountA['id'])
        self.group1 = self.identity_api.create_group(self.group1)

        self.group2 = self.new_group_ref(account_id=self.accountA['id'])
        self.group2 = self.identity_api.create_group(self.group2)

        self.group3 = self.new_group_ref(account_id=self.accountB['id'])
        self.group3 = self.identity_api.create_group(self.group3)

        self.role = self.new_role_ref()
        self.role_api.create_role(self.role['id'], self.role)
        self.role1 = self.new_role_ref()
        self.role_api.create_role(self.role1['id'], self.role1)
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.user1['id'],
                                         account_id=self.accountA['id'])
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.user2['id'],
                                         account_id=self.accountA['id'])
        self.assignment_api.create_grant(self.role1['id'],
                                         user_id=self.user1['id'],
                                         account_id=self.accountA['id'])

    def _get_id_list_from_ref_list(self, ref_list):
        result_list = []
        for x in ref_list:
            result_list.append(x['id'])
        return result_list

    def _set_policy(self, new_policy):
        with open(self.tmpfilename, "w") as policyfile:
            policyfile.write(jsonutils.dumps(new_policy))

    def test_list_users_unprotected(self):
        """GET /users (unprotected)

        Test Plan:

        - Update policy so api is unprotected
        - Use an un-scoped token to make sure we can get back all
          the users independent of account

        """
        self._set_policy({"identity:list_users": []})
        r = self.get('/users', auth=self.auth)
        id_list = self._get_id_list_from_ref_list(r.result.get('users'))
        self.assertIn(self.user1['id'], id_list)
        self.assertIn(self.user2['id'], id_list)
        self.assertIn(self.user3['id'], id_list)

    def test_list_users_filtered_by_account(self):
        """GET /users?account_id=myaccount (filtered)

        Test Plan:

        - Update policy so api is unprotected
        - Use an un-scoped token to make sure we can filter the
          users by accountB, getting back the 2 users in that account

        """
        self._set_policy({"identity:list_users": []})
        url_by_name = '/users?account_id=%s' % self.accountB['id']
        r = self.get(url_by_name, auth=self.auth)
        # We should  get back two users, those in AccountB
        id_list = self._get_id_list_from_ref_list(r.result.get('users'))
        self.assertIn(self.user2['id'], id_list)
        self.assertIn(self.user3['id'], id_list)

    def test_get_user_protected_match_id(self):
        """GET /users/{id} (match payload)

        Test Plan:

        - Update policy to protect api by user_id
        - List users with user_id of user1 as filter, to check that
          this will correctly match user_id in the flattened
          payload

        """
        # TODO(henry-nash, ayoung): It would be good to expand this
        # test for further test flattening, e.g. protect on, say, an
        # attribute of an object being created
        new_policy = {"identity:get_user": [["user_id:%(user_id)s"]]}
        self._set_policy(new_policy)
        url_by_name = '/users/%s' % self.user1['id']
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(self.user1['id'], r.result['user']['id'])

    def test_get_user_protected_match_target(self):
        """GET /users/{id} (match target)

        Test Plan:

        - Update policy to protect api by account_id
        - Try and read a user who is in AccountB with a token scoped
          to Account A - this should fail
        - Retry this for a user who is in Account A, which should succeed.
        - Finally, try getting a user that does not exist, which should
          still return UserNotFound

        """
        new_policy = {'identity:get_user':
                      [["account_id:%(target.user.account_id)s"]]}
        self._set_policy(new_policy)
        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            account_id=self.accountA['id'])
        url_by_name = '/users/%s' % self.user2['id']
        r = self.get(url_by_name, auth=self.auth,
                     expected_status=exception.ForbiddenAction.code)

        url_by_name = '/users/%s' % self.user1['id']
        r = self.get(url_by_name, auth=self.auth)
        self.assertEqual(self.user1['id'], r.result['user']['id'])

        url_by_name = '/users/%s' % uuid.uuid4().hex
        r = self.get(url_by_name, auth=self.auth,
                     expected_status=exception.UserNotFound.code)

    def test_revoke_grant_protected_match_target(self):
        """DELETE /accounts/{id}/users/{id}/roles/{id} (match target)

        Test Plan:

        - Update policy to protect api by account_id of entities in
          the grant
        - Try and delete the existing grant that has a user who is
          from a different account - this should fail.
        - Retry this for a user who is in Account A, which should succeed.

        """
        new_policy = {'identity:revoke_grant':
                      [["account_id:%(target.user.account_id)s"]]}
        self._set_policy(new_policy)
        collection_url = (
            '/accounts/%(account_id)s/users/%(user_id)s/roles' % {
                'account_id': self.accountA['id'],
                'user_id': self.user2['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role['id']}

        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            account_id=self.accountA['id'])
        self.delete(member_url, auth=self.auth,
                    expected_status=exception.ForbiddenAction.code)

        collection_url = (
            '/accounts/%(account_id)s/users/%(user_id)s/roles' % {
                'account_id': self.accountA['id'],
                'user_id': self.user1['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role1['id']}
        self.delete(member_url, auth=self.auth)

    def test_list_users_protected_by_account(self):
        """GET /users?account_id=myaccount (protected)

        Test Plan:

        - Update policy to protect api by account_id
        - List groups using a token scoped to accountA with a filter
          specifying accountA - we should only get back the one user
          that is in accountA.
        - Try and read the users from accountB - this should fail since
          we don't have a token scoped for accountB

        """
        new_policy = {"identity:list_users": ["account_id:%(account_id)s"]}
        self._set_policy(new_policy)
        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            account_id=self.accountA['id'])
        url_by_name = '/users?account_id=%s' % self.accountA['id']
        r = self.get(url_by_name, auth=self.auth)
        # We should only get back one user, the one in AccountA
        id_list = self._get_id_list_from_ref_list(r.result.get('users'))
        self.assertEqual(1, len(id_list))
        self.assertIn(self.user1['id'], id_list)

        # Now try for accountB, which should fail
        url_by_name = '/users?account_id=%s' % self.accountB['id']
        r = self.get(url_by_name, auth=self.auth,
                     expected_status=exception.ForbiddenAction.code)

    def test_list_groups_protected_by_account(self):
        """GET /groups?account_id=myaccount (protected)

        Test Plan:

        - Update policy to protect api by account_id
        - List groups using a token scoped to accountA and make sure
          we only get back the two groups that are in accountA
        - Try and read the groups from accountB - this should fail since
          we don't have a token scoped for accountB

        """
        new_policy = {"identity:list_groups": ["account_id:%(account_id)s"]}
        self._set_policy(new_policy)
        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            account_id=self.accountA['id'])
        url_by_name = '/groups?account_id=%s' % self.accountA['id']
        r = self.get(url_by_name, auth=self.auth)
        # We should only get back two groups, the ones in AccountA
        id_list = self._get_id_list_from_ref_list(r.result.get('groups'))
        self.assertEqual(2, len(id_list))
        self.assertIn(self.group1['id'], id_list)
        self.assertIn(self.group2['id'], id_list)

        # Now try for accountB, which should fail
        url_by_name = '/groups?account_id=%s' % self.accountB['id']
        r = self.get(url_by_name, auth=self.auth,
                     expected_status=exception.ForbiddenAction.code)

    def test_list_groups_protected_by_account_and_filtered(self):
        """GET /groups?account_id=myaccount&name=myname (protected)

        Test Plan:

        - Update policy to protect api by account_id
        - List groups using a token scoped to accountA with a filter
          specifying both accountA and the name of group.
        - We should only get back the group in accountA that matches
          the name

        """
        new_policy = {"identity:list_groups": ["account_id:%(account_id)s"]}
        self._set_policy(new_policy)
        self.auth = self.build_authentication_request(
            user_id=self.user1['id'],
            password=self.user1['password'],
            account_id=self.accountA['id'])
        url_by_name = '/groups?account_id=%s&name=%s' % (
            self.accountA['id'], self.group2['name'])
        r = self.get(url_by_name, auth=self.auth)
        # We should only get back one user, the one in AccountA that matches
        # the name supplied
        id_list = self._get_id_list_from_ref_list(r.result.get('groups'))
        self.assertEqual(1, len(id_list))
        self.assertIn(self.group2['id'], id_list)


class IdentityTestPolicySample(test_v3.RestfulTestCase):
    """Test policy enforcement of the policy.json file."""

    def load_sample_data(self):
        self._populate_default_account()

        self.just_a_user = self.new_user_ref(
            account_id=CONF.identity.default_account_id)
        password = uuid.uuid4().hex
        self.just_a_user['password'] = password
        self.just_a_user = self.identity_api.create_user(self.just_a_user)
        self.just_a_user['password'] = password

        self.another_user = self.new_user_ref(
            account_id=CONF.identity.default_account_id)
        password = uuid.uuid4().hex
        self.another_user['password'] = password
        self.another_user = self.identity_api.create_user(self.another_user)
        self.another_user['password'] = password

        self.admin_user = self.new_user_ref(
            account_id=CONF.identity.default_account_id)
        password = uuid.uuid4().hex
        self.admin_user['password'] = password
        self.admin_user = self.identity_api.create_user(self.admin_user)
        self.admin_user['password'] = password

        self.role = self.new_role_ref()
        self.role_api.create_role(self.role['id'], self.role)
        self.admin_role = {'id': uuid.uuid4().hex, 'name': 'admin'}
        self.role_api.create_role(self.admin_role['id'], self.admin_role)

        # Create and assign roles to the project
        self.project = self.new_project_ref(
            account_id=CONF.identity.default_account_id)
        self.resource_api.create_project(self.project['id'], self.project)
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.just_a_user['id'],
                                         project_id=self.project['id'])
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.another_user['id'],
                                         project_id=self.project['id'])
        self.assignment_api.create_grant(self.admin_role['id'],
                                         user_id=self.admin_user['id'],
                                         project_id=self.project['id'])

    def test_user_validate_same_token(self):
        # Given a non-admin user token, the token can be used to validate
        # itself.
        # This is GET /v3/auth/tokens, with X-Auth-Token == X-Subject-Token
        # FIXME(blk-u): This test fails, a user can't validate their own token,
        # see bug 1421825.

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token = self.get_requested_token(auth)

        # FIXME(blk-u): remove expected_status=403.
        self.get('/auth/tokens', token=token,
                 headers={'X-Subject-Token': token}, expected_status=403)

    def test_user_validate_user_token(self):
        # A user can validate one of their own tokens.
        # This is GET /v3/auth/tokens
        # FIXME(blk-u): This test fails, a user can't validate their own token,
        # see bug 1421825.

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token1 = self.get_requested_token(auth)
        token2 = self.get_requested_token(auth)

        # FIXME(blk-u): remove expected_status=403.
        self.get('/auth/tokens', token=token1,
                 headers={'X-Subject-Token': token2}, expected_status=403)

    def test_user_validate_other_user_token_rejected(self):
        # A user cannot validate another user's token.
        # This is GET /v3/auth/tokens

        user1_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user1_token = self.get_requested_token(user1_auth)

        user2_auth = self.build_authentication_request(
            user_id=self.another_user['id'],
            password=self.another_user['password'])
        user2_token = self.get_requested_token(user2_auth)

        self.get('/auth/tokens', token=user1_token,
                 headers={'X-Subject-Token': user2_token}, expected_status=403)

    def test_admin_validate_user_token(self):
        # An admin can validate a user's token.
        # This is GET /v3/auth/tokens

        admin_auth = self.build_authentication_request(
            user_id=self.admin_user['id'],
            password=self.admin_user['password'],
            project_id=self.project['id'])
        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.get('/auth/tokens', token=admin_token,
                 headers={'X-Subject-Token': user_token})

    def test_user_check_same_token(self):
        # Given a non-admin user token, the token can be used to check
        # itself.
        # This is HEAD /v3/auth/tokens, with X-Auth-Token == X-Subject-Token
        # FIXME(blk-u): This test fails, a user can't check the same token,
        # see bug 1421825.

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token = self.get_requested_token(auth)

        # FIXME(blk-u): change to expected_status=200
        self.head('/auth/tokens', token=token,
                  headers={'X-Subject-Token': token}, expected_status=403)

    def test_user_check_user_token(self):
        # A user can check one of their own tokens.
        # This is HEAD /v3/auth/tokens
        # FIXME(blk-u): This test fails, a user can't check the same token,
        # see bug 1421825.

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token1 = self.get_requested_token(auth)
        token2 = self.get_requested_token(auth)

        # FIXME(blk-u): change to expected_status=200
        self.head('/auth/tokens', token=token1,
                  headers={'X-Subject-Token': token2}, expected_status=403)

    def test_user_check_other_user_token_rejected(self):
        # A user cannot check another user's token.
        # This is HEAD /v3/auth/tokens

        user1_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user1_token = self.get_requested_token(user1_auth)

        user2_auth = self.build_authentication_request(
            user_id=self.another_user['id'],
            password=self.another_user['password'])
        user2_token = self.get_requested_token(user2_auth)

        self.head('/auth/tokens', token=user1_token,
                  headers={'X-Subject-Token': user2_token},
                  expected_status=403)

    def test_admin_check_user_token(self):
        # An admin can check a user's token.
        # This is HEAD /v3/auth/tokens

        admin_auth = self.build_authentication_request(
            user_id=self.admin_user['id'],
            password=self.admin_user['password'],
            project_id=self.project['id'])
        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.head('/auth/tokens', token=admin_token,
                  headers={'X-Subject-Token': user_token}, expected_status=200)

    def test_user_revoke_same_token(self):
        # Given a non-admin user token, the token can be used to revoke
        # itself.
        # This is DELETE /v3/auth/tokens, with X-Auth-Token == X-Subject-Token

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token = self.get_requested_token(auth)

        self.delete('/auth/tokens', token=token,
                    headers={'X-Subject-Token': token})

    def test_user_revoke_user_token(self):
        # A user can revoke one of their own tokens.
        # This is DELETE /v3/auth/tokens

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token1 = self.get_requested_token(auth)
        token2 = self.get_requested_token(auth)

        self.delete('/auth/tokens', token=token1,
                    headers={'X-Subject-Token': token2})

    def test_user_revoke_other_user_token_rejected(self):
        # A user cannot revoke another user's token.
        # This is DELETE /v3/auth/tokens

        user1_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user1_token = self.get_requested_token(user1_auth)

        user2_auth = self.build_authentication_request(
            user_id=self.another_user['id'],
            password=self.another_user['password'])
        user2_token = self.get_requested_token(user2_auth)

        self.delete('/auth/tokens', token=user1_token,
                    headers={'X-Subject-Token': user2_token},
                    expected_status=403)

    def test_admin_revoke_user_token(self):
        # An admin can revoke a user's token.
        # This is DELETE /v3/auth/tokens

        admin_auth = self.build_authentication_request(
            user_id=self.admin_user['id'],
            password=self.admin_user['password'],
            project_id=self.project['id'])
        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.delete('/auth/tokens', token=admin_token,
                    headers={'X-Subject-Token': user_token})


class IdentityTestv3CloudPolicySample(test_v3.RestfulTestCase):
    """Test policy enforcement of the sample v3 cloud policy file."""

    def setUp(self):
        """Setup for v3 Cloud Policy Sample Test Cases.

        The following data is created:

        - Three accounts: accountA, accountB and admin_account
        - One project, which name is 'project'
        - accountA has three users: account_admin_user, project_admin_user and
          just_a_user:

          - account_admin_user has role 'admin' on accountA,
          - project_admin_user has role 'admin' on the project,
          - just_a_user has a non-admin role on both accountA and the project.
        - admin_account has user cloud_admin_user, with an 'admin' role
          on admin_account.

        We test various api protection rules from the cloud sample policy
        file to make sure the sample is valid and that we correctly enforce it.

        """
        # Ensure that test_v3.RestfulTestCase doesn't load its own
        # sample data, which would make checking the results of our
        # tests harder
        super(IdentityTestv3CloudPolicySample, self).setUp()

        # Finally, switch to the v3 sample policy file
        self.addCleanup(rules.reset)
        rules.reset()
        self.config_fixture.config(
            group='oslo_policy',
            policy_file=tests.dirs.etc('policy.v3cloudsample.json'))

    def load_sample_data(self):
        # Start by creating a couple of accounts
        self._populate_default_account()
        self.accountA = self.new_account_ref()
        self.resource_api.create_account(self.accountA['id'], self.accountA)
        self.accountB = self.new_account_ref()
        self.resource_api.create_account(self.accountB['id'], self.accountB)
        self.admin_account = {'id': 'admin_account_id', 'name': 'Admin_account'}
        self.resource_api.create_account(self.admin_account['id'],
                                        self.admin_account)

        # And our users
        self.cloud_admin_user = self.new_user_ref(
            account_id=self.admin_account['id'])
        password = uuid.uuid4().hex
        self.cloud_admin_user['password'] = password
        self.cloud_admin_user = (
            self.identity_api.create_user(self.cloud_admin_user))
        self.cloud_admin_user['password'] = password
        self.just_a_user = self.new_user_ref(account_id=self.accountA['id'])
        password = uuid.uuid4().hex
        self.just_a_user['password'] = password
        self.just_a_user = self.identity_api.create_user(self.just_a_user)
        self.just_a_user['password'] = password
        self.account_admin_user = self.new_user_ref(
            account_id=self.accountA['id'])
        password = uuid.uuid4().hex
        self.account_admin_user['password'] = password
        self.account_admin_user = (
            self.identity_api.create_user(self.account_admin_user))
        self.account_admin_user['password'] = password
        self.project_admin_user = self.new_user_ref(
            account_id=self.accountA['id'])
        password = uuid.uuid4().hex
        self.project_admin_user['password'] = password
        self.project_admin_user = (
            self.identity_api.create_user(self.project_admin_user))
        self.project_admin_user['password'] = password

        # The admin role and another plain role
        self.admin_role = {'id': uuid.uuid4().hex, 'name': 'admin'}
        self.role_api.create_role(self.admin_role['id'], self.admin_role)
        self.role = self.new_role_ref()
        self.role_api.create_role(self.role['id'], self.role)

        # The cloud admin just gets the admin role
        self.assignment_api.create_grant(self.admin_role['id'],
                                         user_id=self.cloud_admin_user['id'],
                                         account_id=self.admin_account['id'])

        # Assign roles to the account
        self.assignment_api.create_grant(self.admin_role['id'],
                                         user_id=self.account_admin_user['id'],
                                         account_id=self.accountA['id'])
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.just_a_user['id'],
                                         account_id=self.accountA['id'])

        # Create and assign roles to the project
        self.project = self.new_project_ref(account_id=self.accountA['id'])
        self.resource_api.create_project(self.project['id'], self.project)
        self.assignment_api.create_grant(self.admin_role['id'],
                                         user_id=self.project_admin_user['id'],
                                         project_id=self.project['id'])
        self.assignment_api.create_grant(self.role['id'],
                                         user_id=self.just_a_user['id'],
                                         project_id=self.project['id'])

    def _stati(self, expected_status):
        # Return the expected return codes for APIs with and without data
        # with any specified status overriding the normal values
        if expected_status is None:
            return (200, 201, 204)
        else:
            return (expected_status, expected_status, expected_status)

    def _test_user_management(self, account_id, expected=None):
        status_OK, status_created, status_no_data = self._stati(expected)
        entity_url = '/users/%s' % self.just_a_user['id']
        list_url = '/users?account_id=%s' % account_id

        self.get(entity_url, auth=self.auth,
                 expected_status=status_OK)
        self.get(list_url, auth=self.auth,
                 expected_status=status_OK)
        user = {'description': 'Updated'}
        self.patch(entity_url, auth=self.auth, body={'user': user},
                   expected_status=status_OK)
        self.delete(entity_url, auth=self.auth,
                    expected_status=status_no_data)

        user_ref = self.new_user_ref(account_id=account_id)
        self.post('/users', auth=self.auth, body={'user': user_ref},
                  expected_status=status_created)

    def _test_project_management(self, account_id, expected=None):
        status_OK, status_created, status_no_data = self._stati(expected)
        entity_url = '/projects/%s' % self.project['id']
        list_url = '/projects?account_id=%s' % account_id

        self.get(entity_url, auth=self.auth,
                 expected_status=status_OK)
        self.get(list_url, auth=self.auth,
                 expected_status=status_OK)
        project = {'description': 'Updated'}
        self.patch(entity_url, auth=self.auth, body={'project': project},
                   expected_status=status_OK)
        self.delete(entity_url, auth=self.auth,
                    expected_status=status_no_data)

        proj_ref = self.new_project_ref(account_id=account_id)
        self.post('/projects', auth=self.auth, body={'project': proj_ref},
                  expected_status=status_created)

    def _test_account_management(self, expected=None):
        status_OK, status_created, status_no_data = self._stati(expected)
        entity_url = '/accounts/%s' % self.accountB['id']
        list_url = '/accounts'

        self.get(entity_url, auth=self.auth,
                 expected_status=status_OK)
        self.get(list_url, auth=self.auth,
                 expected_status=status_OK)
        account = {'description': 'Updated', 'enabled': False}
        self.patch(entity_url, auth=self.auth, body={'account': account},
                   expected_status=status_OK)
        self.delete(entity_url, auth=self.auth,
                    expected_status=status_no_data)

        account_ref = self.new_account_ref()
        self.post('/accounts', auth=self.auth, body={'account': account_ref},
                  expected_status=status_created)

    def _test_grants(self, target, entity_id, expected=None):
        status_OK, status_created, status_no_data = self._stati(expected)
        a_role = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.role_api.create_role(a_role['id'], a_role)

        collection_url = (
            '/%(target)s/%(target_id)s/users/%(user_id)s/roles' % {
                'target': target,
                'target_id': entity_id,
                'user_id': self.just_a_user['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': a_role['id']}

        self.put(member_url, auth=self.auth,
                 expected_status=status_no_data)
        self.head(member_url, auth=self.auth,
                  expected_status=status_no_data)
        self.get(collection_url, auth=self.auth,
                 expected_status=status_OK)
        self.delete(member_url, auth=self.auth,
                    expected_status=status_no_data)

    def test_user_management(self):
        # First, authenticate with a user that does not have the account
        # admin role - shouldn't be able to do much.
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            account_id=self.accountA['id'])

        self._test_user_management(
            self.accountA['id'], expected=exception.ForbiddenAction.code)

        # Now, authenticate with a user that does have the account admin role
        self.auth = self.build_authentication_request(
            user_id=self.account_admin_user['id'],
            password=self.account_admin_user['password'],
            account_id=self.accountA['id'])

        self._test_user_management(self.accountA['id'])

    def test_user_management_by_cloud_admin(self):
        # Test users management with a cloud admin. This user should
        # be able to manage users in any account.
        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            account_id=self.admin_account['id'])

        self._test_user_management(self.accountA['id'])

    def test_project_management(self):
        # First, authenticate with a user that does not have the project
        # admin role - shouldn't be able to do much.
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            account_id=self.accountA['id'])

        self._test_project_management(
            self.accountA['id'], expected=exception.ForbiddenAction.code)

        # ...but should still be able to list projects of which they are
        # a member
        url = '/users/%s/projects' % self.just_a_user['id']
        self.get(url, auth=self.auth)

        # Now, authenticate with a user that does have the account admin role
        self.auth = self.build_authentication_request(
            user_id=self.account_admin_user['id'],
            password=self.account_admin_user['password'],
            account_id=self.accountA['id'])

        self._test_project_management(self.accountA['id'])

    def test_project_management_by_cloud_admin(self):
        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            account_id=self.admin_account['id'])

        # Check whether cloud admin can operate a account
        # other than its own account or not
        self._test_project_management(self.accountA['id'])

    def test_account_grants(self):
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            account_id=self.accountA['id'])

        self._test_grants('accounts', self.accountA['id'],
                          expected=exception.ForbiddenAction.code)

        # Now, authenticate with a user that does have the account admin role
        self.auth = self.build_authentication_request(
            user_id=self.account_admin_user['id'],
            password=self.account_admin_user['password'],
            account_id=self.accountA['id'])

        self._test_grants('accounts', self.accountA['id'])

        # Check that with such a token we cannot modify grants on a
        # different account
        self._test_grants('accounts', self.accountB['id'],
                          expected=exception.ForbiddenAction.code)

    def test_account_grants_by_cloud_admin(self):
        # Test account grants with a cloud admin. This user should be
        # able to manage roles on any account.
        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            account_id=self.admin_account['id'])

        self._test_grants('accounts', self.accountA['id'])

    def test_project_grants(self):
        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            project_id=self.project['id'])

        self._test_grants('projects', self.project['id'],
                          expected=exception.ForbiddenAction.code)

        # Now, authenticate with a user that does have the project
        # admin role
        self.auth = self.build_authentication_request(
            user_id=self.project_admin_user['id'],
            password=self.project_admin_user['password'],
            project_id=self.project['id'])

        self._test_grants('projects', self.project['id'])

    def test_project_grants_by_account_admin(self):
        # Test project grants with a account admin. This user should be
        # able to manage roles on any project in its own account.
        self.auth = self.build_authentication_request(
            user_id=self.account_admin_user['id'],
            password=self.account_admin_user['password'],
            account_id=self.accountA['id'])

        self._test_grants('projects', self.project['id'])

    def test_cloud_admin(self):
        self.auth = self.build_authentication_request(
            user_id=self.account_admin_user['id'],
            password=self.account_admin_user['password'],
            account_id=self.accountA['id'])

        self._test_account_management(
            expected=exception.ForbiddenAction.code)

        self.auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            account_id=self.admin_account['id'])

        self._test_account_management()

    def test_list_user_credentials(self):
        self.credential_user = self.new_credential_ref(self.just_a_user['id'])
        self.credential_api.create_credential(self.credential_user['id'],
                                              self.credential_user)
        self.credential_admin = self.new_credential_ref(
            self.cloud_admin_user['id'])
        self.credential_api.create_credential(self.credential_admin['id'],
                                              self.credential_admin)

        self.auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        url = '/credentials?user_id=%s' % self.just_a_user['id']
        self.get(url, auth=self.auth)
        url = '/credentials?user_id=%s' % self.cloud_admin_user['id']
        self.get(url, auth=self.auth,
                 expected_status=exception.ForbiddenAction.code)
        url = '/credentials'
        self.get(url, auth=self.auth,
                 expected_status=exception.ForbiddenAction.code)

    def test_get_and_delete_ec2_credentials(self):
        """Tests getting and deleting ec2 credentials through the ec2 API."""
        another_user = self.new_user_ref(account_id=self.accountA['id'])
        password = another_user['password']
        another_user = self.identity_api.create_user(another_user)

        # create a credential for just_a_user
        just_user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'],
            project_id=self.project['id'])
        url = '/users/%s/credentials/OS-EC2' % self.just_a_user['id']
        r = self.post(url, body={'tenant_id': self.project['id']},
                      auth=just_user_auth)

        # another normal user can't get the credential
        another_user_auth = self.build_authentication_request(
            user_id=another_user['id'],
            password=password)
        another_user_url = '/users/%s/credentials/OS-EC2/%s' % (
            another_user['id'], r.result['credential']['access'])
        self.get(another_user_url, auth=another_user_auth,
                 expected_status=exception.ForbiddenAction.code)

        # the owner can get the credential
        just_user_url = '/users/%s/credentials/OS-EC2/%s' % (
            self.just_a_user['id'], r.result['credential']['access'])
        self.get(just_user_url, auth=just_user_auth)

        # another normal user can't delete the credential
        self.delete(another_user_url, auth=another_user_auth,
                    expected_status=exception.ForbiddenAction.code)

        # the owner can get the credential
        self.delete(just_user_url, auth=just_user_auth)

    def test_user_validate_same_token(self):
        # Given a non-admin user token, the token can be used to validate
        # itself.
        # This is GET /v3/auth/tokens, with X-Auth-Token == X-Subject-Token
        # FIXME(blk-u): This test fails, a user can't validate their own token,
        # see bug 1421825.

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token = self.get_requested_token(auth)

        # FIXME(blk-u): remove expected_status=403.
        self.get('/auth/tokens', token=token,
                 headers={'X-Subject-Token': token}, expected_status=403)

    def test_user_validate_user_token(self):
        # A user can validate one of their own tokens.
        # This is GET /v3/auth/tokens
        # FIXME(blk-u): This test fails, a user can't validate their own token,
        # see bug 1421825.

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token1 = self.get_requested_token(auth)
        token2 = self.get_requested_token(auth)

        # FIXME(blk-u): remove expected_status=403.
        self.get('/auth/tokens', token=token1,
                 headers={'X-Subject-Token': token2}, expected_status=403)

    def test_user_validate_other_user_token_rejected(self):
        # A user cannot validate another user's token.
        # This is GET /v3/auth/tokens

        user1_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user1_token = self.get_requested_token(user1_auth)

        user2_auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'])
        user2_token = self.get_requested_token(user2_auth)

        self.get('/auth/tokens', token=user1_token,
                 headers={'X-Subject-Token': user2_token}, expected_status=403)

    def test_admin_validate_user_token(self):
        # An admin can validate a user's token.
        # This is GET /v3/auth/tokens

        admin_auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'],
            account_id=self.admin_account['id'])
        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.get('/auth/tokens', token=admin_token,
                 headers={'X-Subject-Token': user_token})

    def test_user_check_same_token(self):
        # Given a non-admin user token, the token can be used to check
        # itself.
        # This is HEAD /v3/auth/tokens, with X-Auth-Token == X-Subject-Token

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token = self.get_requested_token(auth)

        self.head('/auth/tokens', token=token,
                  headers={'X-Subject-Token': token}, expected_status=200)

    def test_user_check_user_token(self):
        # A user can check one of their own tokens.
        # This is HEAD /v3/auth/tokens

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token1 = self.get_requested_token(auth)
        token2 = self.get_requested_token(auth)

        self.head('/auth/tokens', token=token1,
                  headers={'X-Subject-Token': token2}, expected_status=200)

    def test_user_check_other_user_token_rejected(self):
        # A user cannot check another user's token.
        # This is HEAD /v3/auth/tokens

        user1_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user1_token = self.get_requested_token(user1_auth)

        user2_auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'])
        user2_token = self.get_requested_token(user2_auth)

        self.head('/auth/tokens', token=user1_token,
                  headers={'X-Subject-Token': user2_token},
                  expected_status=403)

    def test_admin_check_user_token(self):
        # An admin can check a user's token.
        # This is HEAD /v3/auth/tokens

        admin_auth = self.build_authentication_request(
            user_id=self.account_admin_user['id'],
            password=self.account_admin_user['password'],
            account_id=self.accountA['id'])
        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.head('/auth/tokens', token=admin_token,
                  headers={'X-Subject-Token': user_token}, expected_status=200)

    def test_user_revoke_same_token(self):
        # Given a non-admin user token, the token can be used to revoke
        # itself.
        # This is DELETE /v3/auth/tokens, with X-Auth-Token == X-Subject-Token

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token = self.get_requested_token(auth)

        self.delete('/auth/tokens', token=token,
                    headers={'X-Subject-Token': token})

    def test_user_revoke_user_token(self):
        # A user can revoke one of their own tokens.
        # This is DELETE /v3/auth/tokens

        auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        token1 = self.get_requested_token(auth)
        token2 = self.get_requested_token(auth)

        self.delete('/auth/tokens', token=token1,
                    headers={'X-Subject-Token': token2})

    def test_user_revoke_other_user_token_rejected(self):
        # A user cannot revoke another user's token.
        # This is DELETE /v3/auth/tokens

        user1_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user1_token = self.get_requested_token(user1_auth)

        user2_auth = self.build_authentication_request(
            user_id=self.cloud_admin_user['id'],
            password=self.cloud_admin_user['password'])
        user2_token = self.get_requested_token(user2_auth)

        self.delete('/auth/tokens', token=user1_token,
                    headers={'X-Subject-Token': user2_token},
                    expected_status=403)

    def test_admin_revoke_user_token(self):
        # An admin can revoke a user's token.
        # This is DELETE /v3/auth/tokens

        admin_auth = self.build_authentication_request(
            user_id=self.account_admin_user['id'],
            password=self.account_admin_user['password'],
            account_id=self.accountA['id'])
        admin_token = self.get_requested_token(admin_auth)

        user_auth = self.build_authentication_request(
            user_id=self.just_a_user['id'],
            password=self.just_a_user['password'])
        user_token = self.get_requested_token(user_auth)

        self.delete('/auth/tokens', token=admin_token,
                    headers={'X-Subject-Token': user_token})
