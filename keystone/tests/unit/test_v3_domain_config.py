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

import copy
import uuid

from oslo_config import cfg

from keystone import exception
from keystone.tests.unit import test_v3


CONF = cfg.CONF


class AccountConfigTestCase(test_v3.RestfulTestCase):
    """Test account config support."""

    def setUp(self):
        super(AccountConfigTestCase, self).setUp()

        self.account = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_account(self.account['id'], self.account)
        self.config = {'ldap': {'url': uuid.uuid4().hex,
                                'user_tree_dn': uuid.uuid4().hex},
                       'identity': {'driver': uuid.uuid4().hex}}

    def test_create_config(self):
        """Call ``PUT /accounts/{account_id}/config``."""
        url = '/accounts/%(account_id)s/config' % {
            'account_id': self.account['id']}
        r = self.put(url, body={'config': self.config},
                     expected_status=201)
        res = self.account_config_api.get_config(self.account['id'])
        self.assertEqual(self.config, r.result['config'])
        self.assertEqual(self.config, res)

    def test_create_config_twice(self):
        """Check multiple creates don't throw error"""
        self.put('/accounts/%(account_id)s/config' % {
            'account_id': self.account['id']},
            body={'config': self.config},
            expected_status=201)
        self.put('/accounts/%(account_id)s/config' % {
            'account_id': self.account['id']},
            body={'config': self.config},
            expected_status=200)

    def test_delete_config(self):
        """Call ``DELETE /accounts{account_id}/config``."""
        self.account_config_api.create_config(self.account['id'], self.config)
        self.delete('/accounts/%(account_id)s/config' % {
            'account_id': self.account['id']})
        self.get('/accounts/%(account_id)s/config' % {
            'account_id': self.account['id']},
            expected_status=exception.AccountConfigNotFound.code)

    def test_delete_config_by_group(self):
        """Call ``DELETE /accounts{account_id}/config/{group}``."""
        self.account_config_api.create_config(self.account['id'], self.config)
        self.delete('/accounts/%(account_id)s/config/ldap' % {
            'account_id': self.account['id']})
        res = self.account_config_api.get_config(self.account['id'])
        self.assertNotIn('ldap', res)

    def test_get_head_config(self):
        """Call ``GET & HEAD for /accounts{account_id}/config``."""
        self.account_config_api.create_config(self.account['id'], self.config)
        url = '/accounts/%(account_id)s/config' % {
            'account_id': self.account['id']}
        r = self.get(url)
        self.assertEqual(self.config, r.result['config'])
        self.head(url, expected_status=200)

    def test_get_config_by_group(self):
        """Call ``GET & HEAD /accounts{account_id}/config/{group}``."""
        self.account_config_api.create_config(self.account['id'], self.config)
        url = '/accounts/%(account_id)s/config/ldap' % {
            'account_id': self.account['id']}
        r = self.get(url)
        self.assertEqual({'ldap': self.config['ldap']}, r.result['config'])
        self.head(url, expected_status=200)

    def test_get_config_by_option(self):
        """Call ``GET & HEAD /accounts{account_id}/config/{group}/{option}``."""
        self.account_config_api.create_config(self.account['id'], self.config)
        url = '/accounts/%(account_id)s/config/ldap/url' % {
            'account_id': self.account['id']}
        r = self.get(url)
        self.assertEqual({'url': self.config['ldap']['url']},
                         r.result['config'])
        self.head(url, expected_status=200)

    def test_get_non_existant_config(self):
        """Call ``GET /accounts{account_id}/config when no config defined``."""
        self.get('/accounts/%(account_id)s/config' % {
            'account_id': self.account['id']}, expected_status=404)

    def test_get_non_existant_config_group(self):
        """Call ``GET /accounts{account_id}/config/{group_not_exist}``."""
        config = {'ldap': {'url': uuid.uuid4().hex}}
        self.account_config_api.create_config(self.account['id'], config)
        self.get('/accounts/%(account_id)s/config/identity' % {
            'account_id': self.account['id']}, expected_status=404)

    def test_get_non_existant_config_option(self):
        """Call ``GET /accounts{account_id}/config/group/{option_not_exist}``."""
        config = {'ldap': {'url': uuid.uuid4().hex}}
        self.account_config_api.create_config(self.account['id'], config)
        self.get('/accounts/%(account_id)s/config/ldap/user_tree_dn' % {
            'account_id': self.account['id']}, expected_status=404)

    def test_update_config(self):
        """Call ``PATCH /accounts/{account_id}/config``."""
        self.account_config_api.create_config(self.account['id'], self.config)
        new_config = {'ldap': {'url': uuid.uuid4().hex},
                      'identity': {'driver': uuid.uuid4().hex}}
        r = self.patch('/accounts/%(account_id)s/config' % {
            'account_id': self.account['id']},
            body={'config': new_config})
        res = self.account_config_api.get_config(self.account['id'])
        expected_config = copy.deepcopy(self.config)
        expected_config['ldap']['url'] = new_config['ldap']['url']
        expected_config['identity']['driver'] = (
            new_config['identity']['driver'])
        self.assertEqual(expected_config, r.result['config'])
        self.assertEqual(expected_config, res)

    def test_update_config_group(self):
        """Call ``PATCH /accounts/{account_id}/config/{group}``."""
        self.account_config_api.create_config(self.account['id'], self.config)
        new_config = {'ldap': {'url': uuid.uuid4().hex,
                               'user_filter': uuid.uuid4().hex}}
        r = self.patch('/accounts/%(account_id)s/config/ldap' % {
            'account_id': self.account['id']},
            body={'config': new_config})
        res = self.account_config_api.get_config(self.account['id'])
        expected_config = copy.deepcopy(self.config)
        expected_config['ldap']['url'] = new_config['ldap']['url']
        expected_config['ldap']['user_filter'] = (
            new_config['ldap']['user_filter'])
        self.assertEqual(expected_config, r.result['config'])
        self.assertEqual(expected_config, res)

    def test_update_config_invalid_group(self):
        """Call ``PATCH /accounts/{account_id}/config/{invalid_group}``."""
        self.account_config_api.create_config(self.account['id'], self.config)

        # Trying to update a group that is neither whitelisted or sensitive
        # should result in Forbidden.
        invalid_group = uuid.uuid4().hex
        new_config = {invalid_group: {'url': uuid.uuid4().hex,
                                      'user_filter': uuid.uuid4().hex}}
        self.patch('/accounts/%(account_id)s/config/%(invalid_group)s' % {
            'account_id': self.account['id'], 'invalid_group': invalid_group},
            body={'config': new_config},
            expected_status=403)
        # Trying to update a valid group, but one that is not in the current
        # config should result in NotFound
        config = {'ldap': {'suffix': uuid.uuid4().hex}}
        self.account_config_api.create_config(self.account['id'], config)
        new_config = {'identity': {'driver': uuid.uuid4().hex}}
        self.patch('/accounts/%(account_id)s/config/identity' % {
            'account_id': self.account['id']},
            body={'config': new_config},
            expected_status=404)

    def test_update_config_option(self):
        """Call ``PATCH /accounts/{account_id}/config/{group}/{option}``."""
        self.account_config_api.create_config(self.account['id'], self.config)
        new_config = {'url': uuid.uuid4().hex}
        r = self.patch('/accounts/%(account_id)s/config/ldap/url' % {
            'account_id': self.account['id']},
            body={'config': new_config})
        res = self.account_config_api.get_config(self.account['id'])
        expected_config = copy.deepcopy(self.config)
        expected_config['ldap']['url'] = new_config['url']
        self.assertEqual(expected_config, r.result['config'])
        self.assertEqual(expected_config, res)

    def test_update_config_invalid_option(self):
        """Call ``PATCH /accounts/{account_id}/config/{group}/{invalid}``."""
        self.account_config_api.create_config(self.account['id'], self.config)
        invalid_option = uuid.uuid4().hex
        new_config = {'ldap': {invalid_option: uuid.uuid4().hex}}
        # Trying to update an option that is neither whitelisted or sensitive
        # should result in Forbidden.
        self.patch(
            '/accounts/%(account_id)s/config/ldap/%(invalid_option)s' % {
                'account_id': self.account['id'],
                'invalid_option': invalid_option},
            body={'config': new_config},
            expected_status=403)
        # Trying to update a valid option, but one that is not in the current
        # config should result in NotFound
        new_config = {'suffix': uuid.uuid4().hex}
        self.patch(
            '/accounts/%(account_id)s/config/ldap/suffix' % {
                'account_id': self.account['id']},
            body={'config': new_config},
            expected_status=404)
