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

"""Unit tests for core identity behavior."""

import itertools
import os
import uuid

import mock
from oslo_config import cfg

from keystone import exception
from keystone import identity
from keystone.tests import unit as tests
from keystone.tests.unit.ksfixtures import database


CONF = cfg.CONF


class TestAccountConfigs(tests.BaseTestCase):

    def setUp(self):
        super(TestAccountConfigs, self).setUp()
        self.addCleanup(CONF.reset)

        self.tmp_dir = tests.dirs.tmp()
        CONF.set_override('account_config_dir', self.tmp_dir, 'identity')

    def test_config_for_nonexistent_account(self):
        """Having a config for a non-existent account will be ignored.

        There are no assertions in this test because there are no side
        effects. If there is a config file for a account that does not
        exist it should be ignored.

        """
        account_id = uuid.uuid4().hex
        account_config_filename = os.path.join(self.tmp_dir,
                                              'keystone.%s.conf' % account_id)
        self.addCleanup(lambda: os.remove(account_config_filename))
        with open(account_config_filename, 'w'):
            """Write an empty config file."""

        e = exception.AccountNotFound(account_id=account_id)
        mock_assignment_api = mock.Mock()
        mock_assignment_api.get_account_by_name.side_effect = e

        account_config = identity.AccountConfigs()
        fake_standard_driver = None
        account_config.setup_account_drivers(fake_standard_driver,
                                           mock_assignment_api)

    def test_config_for_dot_name_account(self):
        # Ensure we can get the right account name which has dots within it
        # from filename.
        account_config_filename = os.path.join(self.tmp_dir,
                                              'keystone.abc.def.com.conf')
        with open(account_config_filename, 'w'):
            """Write an empty config file."""
        self.addCleanup(os.remove, account_config_filename)

        with mock.patch.object(identity.AccountConfigs,
                               '_load_config_from_file') as mock_load_config:
            account_config = identity.AccountConfigs()
            fake_assignment_api = None
            fake_standard_driver = None
            account_config.setup_account_drivers(fake_standard_driver,
                                               fake_assignment_api)
            mock_load_config.assert_called_once_with(fake_assignment_api,
                                                     [account_config_filename],
                                                     'abc.def.com')

    def test_config_for_multiple_sql_backend(self):
        accounts_config = identity.AccountConfigs()

        # Create the right sequence of is_sql in the drivers being
        # requested to expose the bug, which is that a False setting
        # means it forgets previous True settings.
        drivers = []
        files = []
        for idx, is_sql in enumerate((True, False, True)):
            drv = mock.Mock(is_sql=is_sql)
            drivers.append(drv)
            name = 'dummy.{0}'.format(idx)
            files.append(''.join((
                identity.ACCOUNT_CONF_FHEAD,
                name,
                identity.ACCOUNT_CONF_FTAIL)))

        walk_fake = lambda *a, **kwa: (
            ('/fake/keystone/accounts/config', [], files), )

        generic_driver = mock.Mock(is_sql=False)

        assignment_api = mock.Mock()
        id_factory = itertools.count()
        assignment_api.get_account_by_name.side_effect = (
            lambda name: {'id': next(id_factory), '_': 'fake_account'})
        load_driver_mock = mock.Mock(side_effect=drivers)

        with mock.patch.object(os, 'walk', walk_fake):
            with mock.patch.object(identity.cfg, 'ConfigOpts'):
                with mock.patch.object(accounts_config, '_load_driver',
                                       load_driver_mock):
                    self.assertRaises(
                        exception.MultipleSQLDriversInConfig,
                        accounts_config.setup_account_drivers,
                        generic_driver, assignment_api)

                    self.assertEqual(3, load_driver_mock.call_count)


class TestDatabaseAccountConfigs(tests.TestCase):

    def setUp(self):
        super(TestDatabaseAccountConfigs, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()

    def test_account_config_in_database_disabled_by_default(self):
        self.assertFalse(CONF.identity.account_configurations_from_database)

    def test_loading_config_from_database(self):
        CONF.set_override('account_configurations_from_database', True,
                          'identity')
        account = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.resource_api.create_account(account['id'], account)
        # Override two config options for our account
        conf = {'ldap': {'url': uuid.uuid4().hex,
                         'suffix': uuid.uuid4().hex},
                'identity': {
                    'driver': 'keystone.identity.backends.ldap.Identity'}}
        self.account_config_api.create_config(account['id'], conf)
        fake_standard_driver = None
        account_config = identity.AccountConfigs()
        account_config.setup_account_drivers(fake_standard_driver,
                                           self.resource_api)
        # Make sure our two overrides are in place, and others are not affected
        res = account_config.get_account_conf(account['id'])
        self.assertEqual(conf['ldap']['url'], res.ldap.url)
        self.assertEqual(conf['ldap']['suffix'], res.ldap.suffix)
        self.assertEqual(CONF.ldap.query_scope, res.ldap.query_scope)

        # Now turn off using database account configuration and check that the
        # default config file values are now seen instead of the overrides.
        CONF.set_override('account_configurations_from_database', False,
                          'identity')
        account_config = identity.AccountConfigs()
        account_config.setup_account_drivers(fake_standard_driver,
                                           self.resource_api)
        res = account_config.get_account_conf(account['id'])
        self.assertEqual(CONF.ldap.url, res.ldap.url)
        self.assertEqual(CONF.ldap.suffix, res.ldap.suffix)
        self.assertEqual(CONF.ldap.query_scope, res.ldap.query_scope)
