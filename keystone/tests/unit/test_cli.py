# Copyright 2014 IBM Corp.
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

import os
import uuid

import mock
from oslo_config import cfg

from keystone import cli
from keystone.common import dependency
from keystone.i18n import _
from keystone import resource
from keystone.tests import unit as tests
from keystone.tests.unit.ksfixtures import database

CONF = cfg.CONF


class CliTestCase(tests.SQLDriverOverrides, tests.TestCase):
    def config_files(self):
        config_files = super(CliTestCase, self).config_files()
        config_files.append(tests.dirs.tests_conf('backend_sql.conf'))
        return config_files

    def test_token_flush(self):
        self.useFixture(database.Database())
        self.load_backends()
        cli.TokenFlush.main()


class CliAccountConfigAllTestCase(tests.SQLDriverOverrides, tests.TestCase):

    def setUp(self):
        self.useFixture(database.Database())
        super(CliAccountConfigAllTestCase, self).setUp()
        self.load_backends()
        self.config_fixture.config(
            group='identity',
            account_config_dir=tests.TESTCONF + '/account_configs_multi_ldap')
        self.account_count = 3
        self.setup_initial_accounts()

    def config_files(self):
        self.config_fixture.register_cli_opt(cli.command_opt)
        self.addCleanup(self.cleanup)
        config_files = super(CliAccountConfigAllTestCase, self).config_files()
        config_files.append(tests.dirs.tests_conf('backend_sql.conf'))
        return config_files

    def cleanup(self):
        CONF.reset()
        CONF.unregister_opt(cli.command_opt)

    def cleanup_accounts(self):
        for account in self.accounts:
            if account == 'account_default':
                # Not allowed to delete the default account, but should at least
                # delete any account-specific config for it.
                self.account_config_api.delete_config(
                    CONF.identity.default_account_id)
                continue
            this_account = self.accounts[account]
            this_account['enabled'] = False
            self.resource_api.update_account(this_account['id'], this_account)
            self.resource_api.delete_account(this_account['id'])
        self.accounts = {}

    def config(self, config_files):
        CONF(args=['account_config_upload', '--all'], project='keystone',
             default_config_files=config_files)

    def setup_initial_accounts(self):

        def create_account(account):
            return self.resource_api.create_account(account['id'], account)

        self.accounts = {}
        self.addCleanup(self.cleanup_accounts)
        for x in range(1, self.account_count):
            account = 'account%s' % x
            self.accounts[account] = create_account(
                {'id': uuid.uuid4().hex, 'name': account})
        self.accounts['account_default'] = create_account(
            resource.calc_default_account())

    def test_config_upload(self):
        # The values below are the same as in the account_configs_multi_ldap
        # directory of test config_files.
        default_config = {
            'ldap': {'url': 'fake://memory',
                     'user': 'cn=Admin',
                     'password': 'password',
                     'suffix': 'cn=example,cn=com'},
            'identity': {'driver': 'keystone.identity.backends.ldap.Identity'}
        }
        account1_config = {
            'ldap': {'url': 'fake://memory1',
                     'user': 'cn=Admin',
                     'password': 'password',
                     'suffix': 'cn=example,cn=com'},
            'identity': {'driver': 'keystone.identity.backends.ldap.Identity'}
        }
        account2_config = {
            'ldap': {'url': 'fake://memory',
                     'user': 'cn=Admin',
                     'password': 'password',
                     'suffix': 'cn=myroot,cn=com',
                     'group_tree_dn': 'ou=UserGroups,dc=myroot,dc=org',
                     'user_tree_dn': 'ou=Users,dc=myroot,dc=org'},
            'identity': {'driver': 'keystone.identity.backends.ldap.Identity'}
        }

        # Clear backend dependencies, since cli loads these manually
        dependency.reset()
        cli.AccountConfigUpload.main()

        res = self.account_config_api.get_config_with_sensitive_info(
            CONF.identity.default_account_id)
        self.assertEqual(default_config, res)
        res = self.account_config_api.get_config_with_sensitive_info(
            self.accounts['account1']['id'])
        self.assertEqual(account1_config, res)
        res = self.account_config_api.get_config_with_sensitive_info(
            self.accounts['account2']['id'])
        self.assertEqual(account2_config, res)


class CliAccountConfigSingleAccountTestCase(CliAccountConfigAllTestCase):

    def config(self, config_files):
        CONF(args=['account_config_upload', '--account-name', 'Default'],
             project='keystone', default_config_files=config_files)

    def test_config_upload(self):
        # The values below are the same as in the account_configs_multi_ldap
        # directory of test config_files.
        default_config = {
            'ldap': {'url': 'fake://memory',
                     'user': 'cn=Admin',
                     'password': 'password',
                     'suffix': 'cn=example,cn=com'},
            'identity': {'driver': 'keystone.identity.backends.ldap.Identity'}
        }

        # Clear backend dependencies, since cli loads these manually
        dependency.reset()
        cli.AccountConfigUpload.main()

        res = self.account_config_api.get_config_with_sensitive_info(
            CONF.identity.default_account_id)
        self.assertEqual(default_config, res)
        res = self.account_config_api.get_config_with_sensitive_info(
            self.accounts['account1']['id'])
        self.assertEqual({}, res)
        res = self.account_config_api.get_config_with_sensitive_info(
            self.accounts['account2']['id'])
        self.assertEqual({}, res)

    def test_no_overwrite_config(self):
        # Create a config for the default account
        default_config = {
            'ldap': {'url': uuid.uuid4().hex},
            'identity': {'driver': 'keystone.identity.backends.ldap.Identity'}
        }
        self.account_config_api.create_config(
            CONF.identity.default_account_id, default_config)

        # Now try and upload the settings in the configuration file for the
        # default account
        dependency.reset()
        with mock.patch('__builtin__.print') as mock_print:
            self.assertRaises(SystemExit, cli.AccountConfigUpload.main)
            file_name = ('keystone.%s.conf' %
                         resource.calc_default_account()['name'])
            error_msg = _(
                'Account: %(account)s already has a configuration defined - '
                'ignoring file: %(file)s.') % {
                    'account': resource.calc_default_account()['name'],
                    'file': os.path.join(CONF.identity.account_config_dir,
                                         file_name)}
            mock_print.assert_has_calls([mock.call(error_msg)])

        res = self.account_config_api.get_config(
            CONF.identity.default_account_id)
        # The initial config should not have been overwritten
        self.assertEqual(default_config, res)


class CliAccountConfigNoOptionsTestCase(CliAccountConfigAllTestCase):

    def config(self, config_files):
        CONF(args=['account_config_upload'],
             project='keystone', default_config_files=config_files)

    def test_config_upload(self):
        dependency.reset()
        with mock.patch('__builtin__.print') as mock_print:
            self.assertRaises(SystemExit, cli.AccountConfigUpload.main)
            mock_print.assert_has_calls(
                [mock.call(
                    _('At least one option must be provided, use either '
                      '--all or --account-name'))])


class CliAccountConfigTooManyOptionsTestCase(CliAccountConfigAllTestCase):

    def config(self, config_files):
        CONF(args=['account_config_upload', '--all', '--account-name',
                   'Default'],
             project='keystone', default_config_files=config_files)

    def test_config_upload(self):
        dependency.reset()
        with mock.patch('__builtin__.print') as mock_print:
            self.assertRaises(SystemExit, cli.AccountConfigUpload.main)
            mock_print.assert_has_calls(
                [mock.call(_('The --all option cannot be used with '
                             'the --account-name option'))])


class CliAccountConfigInvalidAccountTestCase(CliAccountConfigAllTestCase):

    def config(self, config_files):
        self.invalid_account_name = uuid.uuid4().hex
        CONF(args=['account_config_upload', '--account-name',
                   self.invalid_account_name],
             project='keystone', default_config_files=config_files)

    def test_config_upload(self):
        dependency.reset()
        with mock.patch('__builtin__.print') as mock_print:
            self.assertRaises(SystemExit, cli.AccountConfigUpload.main)
            file_name = 'keystone.%s.conf' % self.invalid_account_name
            error_msg = (_(
                'Invalid account name: %(account)s found in config file name: '
                '%(file)s - ignoring this file.') % {
                    'account': self.invalid_account_name,
                    'file': os.path.join(CONF.identity.account_config_dir,
                                         file_name)})
            mock_print.assert_has_calls([mock.call(error_msg)])
