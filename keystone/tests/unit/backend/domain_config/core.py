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

import mock
from testtools import matchers

from keystone import exception
from keystone.tests import unit as tests


class AccountConfigTests(object):

    def setUp(self):
        self.account = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_account(self.account['id'], self.account)
        self.addCleanup(self.clean_up_account)

    def clean_up_account(self):
        # NOTE(henry-nash): Deleting the account will also delete any account
        # configs for this account.
        self.account['enabled'] = False
        self.resource_api.update_account(self.account['id'], self.account)
        self.resource_api.delete_account(self.account['id'])
        del self.account

    def _account_config_crud(self, sensitive):
        group = uuid.uuid4().hex
        option = uuid.uuid4().hex
        value = uuid.uuid4().hex
        self.account_config_api.create_config_option(
            self.account['id'], group, option, value, sensitive)
        res = self.account_config_api.get_config_option(
            self.account['id'], group, option, sensitive)
        config = {'group': group, 'option': option, 'value': value}
        self.assertEqual(config, res)

        value = uuid.uuid4().hex
        self.account_config_api.update_config_option(
            self.account['id'], group, option, value, sensitive)
        res = self.account_config_api.get_config_option(
            self.account['id'], group, option, sensitive)
        config = {'group': group, 'option': option, 'value': value}
        self.assertEqual(config, res)

        self.account_config_api.delete_config_options(
            self.account['id'], group, option, sensitive)
        self.assertRaises(exception.AccountConfigNotFound,
                          self.account_config_api.get_config_option,
                          self.account['id'], group, option, sensitive)
        # ...and silent if we try to delete it again
        self.account_config_api.delete_config_options(
            self.account['id'], group, option, sensitive)

    def test_whitelisted_account_config_crud(self):
        self._account_config_crud(sensitive=False)

    def test_sensitive_account_config_crud(self):
        self._account_config_crud(sensitive=True)

    def _list_account_config(self, sensitive):
        """Test listing by combination of account, group & option."""

        config1 = {'group': uuid.uuid4().hex, 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        # Put config2 in the same group as config1
        config2 = {'group': config1['group'], 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        config3 = {'group': uuid.uuid4().hex, 'option': uuid.uuid4().hex,
                   'value': 100}
        for config in [config1, config2, config3]:
            self.account_config_api.create_config_option(
                self.account['id'], config['group'], config['option'],
                config['value'], sensitive)

        # Try listing all items from a account
        res = self.account_config_api.list_config_options(
            self.account['id'], sensitive=sensitive)
        self.assertThat(res, matchers.HasLength(3))
        for res_entry in res:
            self.assertIn(res_entry, [config1, config2, config3])

        # Try listing by account and group
        res = self.account_config_api.list_config_options(
            self.account['id'], group=config1['group'], sensitive=sensitive)
        self.assertThat(res, matchers.HasLength(2))
        for res_entry in res:
            self.assertIn(res_entry, [config1, config2])

        # Try listing by account, group and option
        res = self.account_config_api.list_config_options(
            self.account['id'], group=config2['group'],
            option=config2['option'], sensitive=sensitive)
        self.assertThat(res, matchers.HasLength(1))
        self.assertEqual(config2, res[0])

    def test_list_whitelisted_account_config_crud(self):
        self._list_account_config(False)

    def test_list_sensitive_account_config_crud(self):
        self._list_account_config(True)

    def _delete_account_configs(self, sensitive):
        """Test deleting by combination of account, group & option."""

        config1 = {'group': uuid.uuid4().hex, 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        # Put config2 and config3 in the same group as config1
        config2 = {'group': config1['group'], 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        config3 = {'group': config1['group'], 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        config4 = {'group': uuid.uuid4().hex, 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        for config in [config1, config2, config3, config4]:
            self.account_config_api.create_config_option(
                self.account['id'], config['group'], config['option'],
                config['value'], sensitive)

        # Try deleting by account, group and option
        res = self.account_config_api.delete_config_options(
            self.account['id'], group=config2['group'],
            option=config2['option'], sensitive=sensitive)
        res = self.account_config_api.list_config_options(
            self.account['id'], sensitive=sensitive)
        self.assertThat(res, matchers.HasLength(3))
        for res_entry in res:
            self.assertIn(res_entry, [config1, config3, config4])

        # Try deleting by account and group
        res = self.account_config_api.delete_config_options(
            self.account['id'], group=config4['group'], sensitive=sensitive)
        res = self.account_config_api.list_config_options(
            self.account['id'], sensitive=sensitive)
        self.assertThat(res, matchers.HasLength(2))
        for res_entry in res:
            self.assertIn(res_entry, [config1, config3])

        # Try deleting all items from a account
        res = self.account_config_api.delete_config_options(
            self.account['id'], sensitive=sensitive)
        res = self.account_config_api.list_config_options(
            self.account['id'], sensitive=sensitive)
        self.assertThat(res, matchers.HasLength(0))

    def test_delete_whitelisted_account_configs(self):
        self._delete_account_configs(False)

    def test_delete_sensitive_account_configs(self):
        self._delete_account_configs(True)

    def _create_account_config_twice(self, sensitive):
        """Test conflict error thrown if create the same option twice."""

        config = {'group': uuid.uuid4().hex, 'option': uuid.uuid4().hex,
                  'value': uuid.uuid4().hex}

        self.account_config_api.create_config_option(
            self.account['id'], config['group'], config['option'],
            config['value'], sensitive=sensitive)
        self.assertRaises(exception.Conflict,
                          self.account_config_api.create_config_option,
                          self.account['id'], config['group'], config['option'],
                          config['value'], sensitive=sensitive)

    def test_create_whitelisted_account_config_twice(self):
        self._create_account_config_twice(False)

    def test_create_sensitive_account_config_twice(self):
        self._create_account_config_twice(True)

    def test_delete_account_deletes_configs(self):
        """Test account deletion clears the account configs."""

        account = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_account(account['id'], account)
        config1 = {'group': uuid.uuid4().hex, 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        # Put config2 in the same group as config1
        config2 = {'group': config1['group'], 'option': uuid.uuid4().hex,
                   'value': uuid.uuid4().hex}
        self.account_config_api.create_config_option(
            account['id'], config1['group'], config1['option'],
            config1['value'])
        self.account_config_api.create_config_option(
            account['id'], config2['group'], config2['option'],
            config2['value'], sensitive=True)
        res = self.account_config_api.list_config_options(
            account['id'])
        self.assertThat(res, matchers.HasLength(1))
        res = self.account_config_api.list_config_options(
            account['id'], sensitive=True)
        self.assertThat(res, matchers.HasLength(1))

        # Now delete the account
        account['enabled'] = False
        self.resource_api.update_account(account['id'], account)
        self.resource_api.delete_account(account['id'])

        # Check account configs have also been deleted
        res = self.account_config_api.list_config_options(
            account['id'])
        self.assertThat(res, matchers.HasLength(0))
        res = self.account_config_api.list_config_options(
            account['id'], sensitive=True)
        self.assertThat(res, matchers.HasLength(0))

    def test_create_account_config_including_sensitive_option(self):
        config = {'ldap': {'url': uuid.uuid4().hex,
                           'user_tree_dn': uuid.uuid4().hex,
                           'password': uuid.uuid4().hex}}
        self.account_config_api.create_config(self.account['id'], config)

        # password is sensitive, so check that the whitelisted portion and
        # the sensitive piece have been stored in the appropriate locations.
        res = self.account_config_api.get_config(self.account['id'])
        config_whitelisted = copy.deepcopy(config)
        config_whitelisted['ldap'].pop('password')
        self.assertEqual(config_whitelisted, res)
        res = self.account_config_api.get_config_option(
            self.account['id'], 'ldap', 'password', sensitive=True)
        self.assertEqual(config['ldap']['password'], res['value'])

        # Finally, use the non-public API to get back the whole config
        res = self.account_config_api.get_config_with_sensitive_info(
            self.account['id'])
        self.assertEqual(config, res)

    def test_get_partial_account_config(self):
        config = {'ldap': {'url': uuid.uuid4().hex,
                           'user_tree_dn': uuid.uuid4().hex,
                           'password': uuid.uuid4().hex},
                  'identity': {'driver': uuid.uuid4().hex}}
        self.account_config_api.create_config(self.account['id'], config)

        res = self.account_config_api.get_config(self.account['id'],
                                                group='identity')
        config_partial = copy.deepcopy(config)
        config_partial.pop('ldap')
        self.assertEqual(config_partial, res)
        res = self.account_config_api.get_config(
            self.account['id'], group='ldap', option='user_tree_dn')
        self.assertEqual({'user_tree_dn': config['ldap']['user_tree_dn']}, res)
        # ...but we should fail to get a sensitive option
        self.assertRaises(exception.AccountConfigNotFound,
                          self.account_config_api.get_config, self.account['id'],
                          group='ldap', option='password')

    def test_delete_partial_account_config(self):
        config = {'ldap': {'url': uuid.uuid4().hex,
                           'user_tree_dn': uuid.uuid4().hex,
                           'password': uuid.uuid4().hex},
                  'identity': {'driver': uuid.uuid4().hex}}
        self.account_config_api.create_config(self.account['id'], config)

        self.account_config_api.delete_config(
            self.account['id'], group='identity')
        config_partial = copy.deepcopy(config)
        config_partial.pop('identity')
        config_partial['ldap'].pop('password')
        res = self.account_config_api.get_config(self.account['id'])
        self.assertEqual(config_partial, res)

        self.account_config_api.delete_config(
            self.account['id'], group='ldap', option='url')
        config_partial = copy.deepcopy(config_partial)
        config_partial['ldap'].pop('url')
        res = self.account_config_api.get_config(self.account['id'])
        self.assertEqual(config_partial, res)

    def test_get_options_not_in_account_config(self):
        self.assertRaises(exception.AccountConfigNotFound,
                          self.account_config_api.get_config, self.account['id'])
        config = {'ldap': {'url': uuid.uuid4().hex}}

        self.account_config_api.create_config(self.account['id'], config)

        self.assertRaises(exception.AccountConfigNotFound,
                          self.account_config_api.get_config, self.account['id'],
                          group='identity')
        self.assertRaises(exception.AccountConfigNotFound,
                          self.account_config_api.get_config, self.account['id'],
                          group='ldap', option='user_tree_dn')

    def test_get_sensitive_config(self):
        config = {'ldap': {'url': uuid.uuid4().hex,
                           'user_tree_dn': uuid.uuid4().hex,
                           'password': uuid.uuid4().hex},
                  'identity': {'driver': uuid.uuid4().hex}}
        res = self.account_config_api.get_config_with_sensitive_info(
            self.account['id'])
        self.assertEqual({}, res)
        self.account_config_api.create_config(self.account['id'], config)
        res = self.account_config_api.get_config_with_sensitive_info(
            self.account['id'])
        self.assertEqual(config, res)

    def test_update_partial_account_config(self):
        config = {'ldap': {'url': uuid.uuid4().hex,
                           'user_tree_dn': uuid.uuid4().hex,
                           'password': uuid.uuid4().hex},
                  'identity': {'driver': uuid.uuid4().hex}}
        self.account_config_api.create_config(self.account['id'], config)

        # Try updating a group
        new_config = {'ldap': {'url': uuid.uuid4().hex,
                               'user_filter': uuid.uuid4().hex}}
        res = self.account_config_api.update_config(
            self.account['id'], new_config, group='ldap')
        expected_config = copy.deepcopy(config)
        expected_config['ldap']['url'] = new_config['ldap']['url']
        expected_config['ldap']['user_filter'] = (
            new_config['ldap']['user_filter'])
        expected_full_config = copy.deepcopy(expected_config)
        expected_config['ldap'].pop('password')
        res = self.account_config_api.get_config(self.account['id'])
        self.assertEqual(expected_config, res)
        # The sensitive option should still existsss
        res = self.account_config_api.get_config_with_sensitive_info(
            self.account['id'])
        self.assertEqual(expected_full_config, res)

        # Try updating a single whitelisted option
        self.account_config_api.delete_config(self.account['id'])
        self.account_config_api.create_config(self.account['id'], config)
        new_config = {'url': uuid.uuid4().hex}
        res = self.account_config_api.update_config(
            self.account['id'], new_config, group='ldap', option='url')

        # Make sure whitelisted and full config is updated
        expected_whitelisted_config = copy.deepcopy(config)
        expected_whitelisted_config['ldap']['url'] = new_config['url']
        expected_full_config = copy.deepcopy(expected_whitelisted_config)
        expected_whitelisted_config['ldap'].pop('password')
        self.assertEqual(expected_whitelisted_config, res)
        res = self.account_config_api.get_config(self.account['id'])
        self.assertEqual(expected_whitelisted_config, res)
        res = self.account_config_api.get_config_with_sensitive_info(
            self.account['id'])
        self.assertEqual(expected_full_config, res)

        # Try updating a single sensitive option
        self.account_config_api.delete_config(self.account['id'])
        self.account_config_api.create_config(self.account['id'], config)
        new_config = {'password': uuid.uuid4().hex}
        res = self.account_config_api.update_config(
            self.account['id'], new_config, group='ldap', option='password')
        # The whitelisted config should not have changed...
        expected_whitelisted_config = copy.deepcopy(config)
        expected_full_config = copy.deepcopy(config)
        expected_whitelisted_config['ldap'].pop('password')
        self.assertEqual(expected_whitelisted_config, res)
        res = self.account_config_api.get_config(self.account['id'])
        self.assertEqual(expected_whitelisted_config, res)
        expected_full_config['ldap']['password'] = new_config['password']
        res = self.account_config_api.get_config_with_sensitive_info(
            self.account['id'])
        # ...but the sensitive piece should have.
        self.assertEqual(expected_full_config, res)

    def test_update_invalid_partial_account_config(self):
        config = {'ldap': {'url': uuid.uuid4().hex,
                           'user_tree_dn': uuid.uuid4().hex,
                           'password': uuid.uuid4().hex},
                  'identity': {'driver': uuid.uuid4().hex}}
        # An extra group, when specifying one group should fail
        self.assertRaises(exception.InvalidAccountConfig,
                          self.account_config_api.update_config,
                          self.account['id'], config, group='ldap')
        # An extra option, when specifying one option should fail
        self.assertRaises(exception.InvalidAccountConfig,
                          self.account_config_api.update_config,
                          self.account['id'], config['ldap'],
                          group='ldap', option='url')

        # Now try the right number of groups/options, but just not
        # ones that are in the config provided
        config = {'ldap': {'user_tree_dn': uuid.uuid4().hex}}
        self.assertRaises(exception.InvalidAccountConfig,
                          self.account_config_api.update_config,
                          self.account['id'], config, group='identity')
        self.assertRaises(exception.InvalidAccountConfig,
                          self.account_config_api.update_config,
                          self.account['id'], config['ldap'], group='ldap',
                          option='url')

        # Now some valid groups/options, but just not ones that are in the
        # existing config
        config = {'ldap': {'user_tree_dn': uuid.uuid4().hex}}
        self.account_config_api.create_config(self.account['id'], config)
        config_wrong_group = {'identity': {'driver': uuid.uuid4().hex}}
        self.assertRaises(exception.AccountConfigNotFound,
                          self.account_config_api.update_config,
                          self.account['id'], config_wrong_group,
                          group='identity')
        config_wrong_option = {'url': uuid.uuid4().hex}
        self.assertRaises(exception.AccountConfigNotFound,
                          self.account_config_api.update_config,
                          self.account['id'], config_wrong_option,
                          group='ldap', option='url')

        # And finally just some bad groups/options
        bad_group = uuid.uuid4().hex
        config = {bad_group: {'user': uuid.uuid4().hex}}
        self.assertRaises(exception.InvalidAccountConfig,
                          self.account_config_api.update_config,
                          self.account['id'], config, group=bad_group,
                          option='user')
        bad_option = uuid.uuid4().hex
        config = {'ldap': {bad_option: uuid.uuid4().hex}}
        self.assertRaises(exception.InvalidAccountConfig,
                          self.account_config_api.update_config,
                          self.account['id'], config, group='ldap',
                          option=bad_option)

    def test_create_invalid_account_config(self):
        self.assertRaises(exception.InvalidAccountConfig,
                          self.account_config_api.create_config,
                          self.account['id'], {})
        config = {uuid.uuid4().hex: uuid.uuid4().hex}
        self.assertRaises(exception.InvalidAccountConfig,
                          self.account_config_api.create_config,
                          self.account['id'], config)
        config = {uuid.uuid4().hex: {uuid.uuid4().hex: uuid.uuid4().hex}}
        self.assertRaises(exception.InvalidAccountConfig,
                          self.account_config_api.create_config,
                          self.account['id'], config)
        config = {'ldap': {uuid.uuid4().hex: uuid.uuid4().hex}}
        self.assertRaises(exception.InvalidAccountConfig,
                          self.account_config_api.create_config,
                          self.account['id'], config)
        # Try an option that IS in the standard conf, but neither whitelisted
        # or marked as sensitive
        config = {'ldap': {'role_tree_dn': uuid.uuid4().hex}}
        self.assertRaises(exception.InvalidAccountConfig,
                          self.account_config_api.create_config,
                          self.account['id'], config)

    def test_delete_invalid_partial_account_config(self):
        config = {'ldap': {'url': uuid.uuid4().hex}}
        self.account_config_api.create_config(self.account['id'], config)
        # Try deleting a group not in the config
        self.assertRaises(exception.AccountConfigNotFound,
                          self.account_config_api.delete_config,
                          self.account['id'], group='identity')
        # Try deleting an option not in the config
        self.assertRaises(exception.AccountConfigNotFound,
                          self.account_config_api.delete_config,
                          self.account['id'],
                          group='ldap', option='user_tree_dn')

    def test_sensitive_substitution_in_account_config(self):
        # Create a config that contains a whitelisted option that requires
        # substitution of a sensitive option.
        config = {'ldap': {'url': 'my_url/%(password)s',
                           'user_tree_dn': uuid.uuid4().hex,
                           'password': uuid.uuid4().hex},
                  'identity': {'driver': uuid.uuid4().hex}}
        self.account_config_api.create_config(self.account['id'], config)

        # Read back the config with the internal method and ensure that the
        # substitution has taken place.
        res = self.account_config_api.get_config_with_sensitive_info(
            self.account['id'])
        expected_url = (
            config['ldap']['url'] % {'password': config['ldap']['password']})
        self.assertEqual(expected_url, res['ldap']['url'])

    def test_invalid_sensitive_substitution_in_account_config(self):
        """Check that invalid substitutions raise warnings."""

        mock_log = mock.Mock()

        invalid_option_config = {
            'ldap': {'user_tree_dn': uuid.uuid4().hex,
                     'password': uuid.uuid4().hex},
            'identity': {'driver': uuid.uuid4().hex}}

        for invalid_option in ['my_url/%(passssword)s',
                               'my_url/%(password',
                               'my_url/%(password)',
                               'my_url/%(password)d']:
            invalid_option_config['ldap']['url'] = invalid_option
            self.account_config_api.create_config(
                self.account['id'], invalid_option_config)

            with mock.patch('keystone.resource.core.LOG', mock_log):
                res = self.account_config_api.get_config_with_sensitive_info(
                    self.account['id'])
            mock_log.warn.assert_any_call(mock.ANY)
            self.assertEqual(
                invalid_option_config['ldap']['url'], res['ldap']['url'])

    def test_escaped_sequence_in_account_config(self):
        """Check that escaped '%(' doesn't get interpreted."""

        mock_log = mock.Mock()

        escaped_option_config = {
            'ldap': {'url': 'my_url/%%(password)s',
                     'user_tree_dn': uuid.uuid4().hex,
                     'password': uuid.uuid4().hex},
            'identity': {'driver': uuid.uuid4().hex}}

        self.account_config_api.create_config(
            self.account['id'], escaped_option_config)

        with mock.patch('keystone.resource.core.LOG', mock_log):
            res = self.account_config_api.get_config_with_sensitive_info(
                self.account['id'])
        self.assertFalse(mock_log.warn.called)
        # The escaping '%' should have been removed
        self.assertEqual('my_url/%(password)s', res['ldap']['url'])

    @tests.skip_if_cache_disabled('account_config')
    def test_cache_layer_get_sensitive_config(self):
        config = {'ldap': {'url': uuid.uuid4().hex,
                           'user_tree_dn': uuid.uuid4().hex,
                           'password': uuid.uuid4().hex},
                  'identity': {'driver': uuid.uuid4().hex}}
        self.account_config_api.create_config(self.account['id'], config)
        # cache the result
        res = self.account_config_api.get_config_with_sensitive_info(
            self.account['id'])
        self.assertEqual(config, res)

        # delete, bypassing account config manager api
        self.account_config_api.delete_config_options(self.account['id'])
        self.account_config_api.delete_config_options(self.account['id'],
                                                     sensitive=True)

        self.assertDictEqual(
            res, self.account_config_api.get_config_with_sensitive_info(
                self.account['id']))
        self.account_config_api.get_config_with_sensitive_info.invalidate(
            self.account_config_api, self.account['id'])
        self.assertDictEqual(
            {},
            self.account_config_api.get_config_with_sensitive_info(
                self.account['id']))
