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

from __future__ import absolute_import
from __future__ import print_function

import os

from oslo_config import cfg
from oslo_log import log
import pbr.version

from keystone import backends
from keystone.common import driver_hints
from keystone.common import openssl
from keystone.common import sql
from keystone.common.sql import migration_helpers
from keystone.common import utils
from keystone import config
from keystone import exception
from keystone.i18n import _, _LW
from keystone import token


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class BaseApp(object):

    name = None

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = subparsers.add_parser(cls.name, help=cls.__doc__)
        parser.set_defaults(cmd_class=cls)
        return parser


class DbSync(BaseApp):
    """Sync the database."""

    name = 'db_sync'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(DbSync, cls).add_argument_parser(subparsers)
        parser.add_argument('version', default=None, nargs='?',
                            help=('Migrate the database up to a specified '
                                  'version. If not provided, db_sync will '
                                  'migrate the database to the latest known '
                                  'version. Schema downgrades are not '
                                  'supported.'))
        parser.add_argument('--extension', default=None,
                            help=('Migrate the database for the specified '
                                  'extension. If not provided, db_sync will '
                                  'migrate the common repository.'))

        return parser

    @staticmethod
    def main():
        version = CONF.command.version
        extension = CONF.command.extension
        migration_helpers.sync_database_to_version(extension, version)


class DbVersion(BaseApp):
    """Print the current migration version of the database."""

    name = 'db_version'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(DbVersion, cls).add_argument_parser(subparsers)
        parser.add_argument('--extension', default=None,
                            help=('Print the migration version of the '
                                  'database for the specified extension. If '
                                  'not provided, print it for the common '
                                  'repository.'))

    @staticmethod
    def main():
        extension = CONF.command.extension
        migration_helpers.print_db_version(extension)


class BasePermissionsSetup(BaseApp):
    """Common user/group setup for file permissions."""

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(BasePermissionsSetup,
                       cls).add_argument_parser(subparsers)
        running_as_root = (os.geteuid() == 0)
        parser.add_argument('--keystone-user', required=running_as_root)
        parser.add_argument('--keystone-group', required=running_as_root)
        return parser

    @staticmethod
    def get_user_group():
        keystone_user_id = None
        keystone_group_id = None

        try:
            a = CONF.command.keystone_user
            if a:
                keystone_user_id = utils.get_unix_user(a)[0]
        except KeyError:
            raise ValueError("Unknown user '%s' in --keystone-user" % a)

        try:
            a = CONF.command.keystone_group
            if a:
                keystone_group_id = utils.get_unix_group(a)[0]
        except KeyError:
            raise ValueError("Unknown group '%s' in --keystone-group" % a)

        return keystone_user_id, keystone_group_id


class BaseCertificateSetup(BasePermissionsSetup):
    """Provides common options for certificate setup."""

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(BaseCertificateSetup,
                       cls).add_argument_parser(subparsers)
        parser.add_argument('--rebuild', default=False, action='store_true',
                            help=('Rebuild certificate files: erase previous '
                                  'files and regenerate them.'))
        return parser


class PKISetup(BaseCertificateSetup):
    """Set up Key pairs and certificates for token signing and verification.

    This is NOT intended for production use, see Keystone Configuration
    documentation for details.
    """

    name = 'pki_setup'

    @classmethod
    def main(cls):
        LOG.warn(_LW('keystone-manage pki_setup is not recommended for '
                     'production use.'))
        keystone_user_id, keystone_group_id = cls.get_user_group()
        conf_pki = openssl.ConfigurePKI(keystone_user_id, keystone_group_id,
                                        rebuild=CONF.command.rebuild)
        conf_pki.run()


class SSLSetup(BaseCertificateSetup):
    """Create key pairs and certificates for HTTPS connections.

    This is NOT intended for production use, see Keystone Configuration
    documentation for details.
    """

    name = 'ssl_setup'

    @classmethod
    def main(cls):
        LOG.warn(_LW('keystone-manage ssl_setup is not recommended for '
                     'production use.'))
        keystone_user_id, keystone_group_id = cls.get_user_group()
        conf_ssl = openssl.ConfigureSSL(keystone_user_id, keystone_group_id,
                                        rebuild=CONF.command.rebuild)
        conf_ssl.run()


class FernetSetup(BasePermissionsSetup):
    """Setup a key repository for Fernet tokens.

    This also creates a primary key used for both creating and validating
    Keystone Lightweight tokens. To improve security, you should rotate your
    keys (using keystone-manage fernet_rotate, for example).

    """

    name = 'fernet_setup'

    @classmethod
    def main(cls):
        from keystone.token.providers.fernet import utils as fernet

        keystone_user_id, keystone_group_id = cls.get_user_group()
        fernet.create_key_directory(keystone_user_id, keystone_group_id)
        if fernet.validate_key_repository():
            fernet.initialize_key_repository(
                keystone_user_id, keystone_group_id)


class FernetRotate(BasePermissionsSetup):
    """Rotate Fernet encryption keys.

    This assumes you have already run keystone-manage fernet_setup.

    A new primary key is placed into rotation, which is used for new tokens.
    The old primary key is demoted to secondary, which can then still be used
    for validating tokens. Excess secondary keys (beyond [fernet_tokens]
    max_active_keys) are revoked. Revoked keys are permanently deleted. A new
    staged key will be created and used to validate tokens. The next time key
    rotation takes place, the staged key will be put into rotation as the
    primary key.

    Rotating keys too frequently, or with [fernet_tokens] max_active_keys set
    too low, will cause tokens to become invalid prior to their expiration.

    """

    name = 'fernet_rotate'

    @classmethod
    def main(cls):
        from keystone.token.providers.fernet import utils as fernet

        keystone_user_id, keystone_group_id = cls.get_user_group()
        if fernet.validate_key_repository():
            fernet.rotate_keys(keystone_user_id, keystone_group_id)


class TokenFlush(BaseApp):
    """Flush expired tokens from the backend."""

    name = 'token_flush'

    @classmethod
    def main(cls):
        token_manager = token.persistence.PersistenceManager()
        token_manager.flush_expired_tokens()


class MappingPurge(BaseApp):
    """Purge the mapping table."""

    name = 'mapping_purge'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(MappingPurge, cls).add_argument_parser(subparsers)
        parser.add_argument('--all', default=False, action='store_true',
                            help=('Purge all mappings.'))
        parser.add_argument('--account-name', default=None,
                            help=('Purge any mappings for the account '
                                  'specified.'))
        parser.add_argument('--public-id', default=None,
                            help=('Purge the mapping for the Public ID '
                                  'specified.'))
        parser.add_argument('--local-id', default=None,
                            help=('Purge the mappings for the Local ID '
                                  'specified.'))
        parser.add_argument('--type', default=None, choices=['user', 'group'],
                            help=('Purge any mappings for the type '
                                  'specified.'))
        return parser

    @staticmethod
    def main():
        def validate_options():
            # NOTE(henry-nash); It would be nice to use the argparse automated
            # checking for this validation, but the only way I can see doing
            # that is to make the default (i.e. if no optional parameters
            # are specified) to purge all mappings - and that sounds too
            # dangerous as a default.  So we use it in a slightly
            # unconventional way, where all parameters are optional, but you
            # must specify at least one.
            if (CONF.command.all is False and
                CONF.command.account_name is None and
                CONF.command.public_id is None and
                CONF.command.local_id is None and
                    CONF.command.type is None):
                raise ValueError(_('At least one option must be provided'))

            if (CONF.command.all is True and
                (CONF.command.account_name is not None or
                 CONF.command.public_id is not None or
                 CONF.command.local_id is not None or
                 CONF.command.type is not None)):
                raise ValueError(_('--all option cannot be mixed with '
                                   'other options'))

        def get_account_id(name):
            try:
                return resource_manager.get_account_by_name(name)['id']
            except KeyError:
                raise ValueError(_("Unknown account '%(name)s' specified by "
                                   "--account-name") % {'name': name})

        validate_options()
        drivers = backends.load_backends()
        resource_manager = drivers['resource_api']
        mapping_manager = drivers['id_mapping_api']

        # Now that we have validated the options, we know that at least one
        # option has been specified, and if it was the --all option then this
        # was the only option specified.
        #
        # The mapping dict is used to filter which mappings are purged, so
        # leaving it empty means purge them all
        mapping = {}
        if CONF.command.account_name is not None:
            mapping['account_id'] = get_account_id(CONF.command.account_name)
        if CONF.command.public_id is not None:
            mapping['public_id'] = CONF.command.public_id
        if CONF.command.local_id is not None:
            mapping['local_id'] = CONF.command.local_id
        if CONF.command.type is not None:
            mapping['type'] = CONF.command.type

        mapping_manager.purge_mappings(mapping)


ACCOUNT_CONF_FHEAD = 'keystone.'
ACCOUNT_CONF_FTAIL = '.conf'


class AccountConfigUploadFiles(object):

    def __init__(self):
        super(AccountConfigUploadFiles, self).__init__()
        self.load_backends()

    def load_backends(self):
        drivers = backends.load_backends()
        self.resource_manager = drivers['resource_api']
        self.account_config_manager = drivers['account_config_api']

    def valid_options(self):
        """Validate the options, returning True if they are indeed valid.

        It would be nice to use the argparse automated checking for this
        validation, but the only way I can see doing that is to make the
        default (i.e. if no optional parameters are specified) to upload
        all configuration files - and that sounds too dangerous as a
        default. So we use it in a slightly unconventional way, where all
        parameters are optional, but you must specify at least one.

        """
        if (CONF.command.all is False and
                CONF.command.account_name is None):
            print(_('At least one option must be provided, use either '
                    '--all or --account-name'))
            raise ValueError

        if (CONF.command.all is True and
                CONF.command.account_name is not None):
            print(_('The --all option cannot be used with '
                    'the --account-name option'))
            raise ValueError

    def upload_config_to_database(self, file_name, account_name):
        """Upload a single config file to the database.

        :param file_name: the file containing the config options
        :param account_name: the account name

        :raises: ValueError: the account does not exist or already has account
                             specific configurations defined
        :raises: Exceptions from oslo config: there is an issue with options
                                              defined in the config file or its
                                              format

        The caller of this method should catch the errors raised and handle
        appropriately in order that the best UX experience can be provided for
        both the case of when a user has asked for a specific config file to
        be uploaded, as well as all config files in a directory.

        """
        try:
            account_ref = (
                self.resource_manager.get_account_by_name(account_name))
        except exception.AccountNotFound:
            print(_('Invalid account name: %(account)s found in config file '
                    'name: %(file)s - ignoring this file.') % {
                        'account': account_name,
                        'file': file_name})
            raise ValueError

        if self.account_config_manager.get_config_with_sensitive_info(
                account_ref['id']):
            print(_('Account: %(account)s already has a configuration '
                    'defined - ignoring file: %(file)s.') % {
                        'account': account_name,
                        'file': file_name})
            raise ValueError

        sections = {}
        try:
            parser = cfg.ConfigParser(file_name, sections)
            parser.parse()
        except Exception:
            # We explicitly don't try and differentiate the error cases, in
            # order to keep the code in this tool more robust as oslo.config
            # changes.
            print(_('Error parsing configuration file for account: %(account)s, '
                    'file: %(file)s.') % {
                        'account': account_name,
                        'file': file_name})
            raise

        for group in sections:
            for option in sections[group]:
                    sections[group][option] = sections[group][option][0]
        self.account_config_manager.create_config(account_ref['id'], sections)

    def upload_configs_to_database(self, file_name, account_name):
        """Upload configs from file and load into database.

        This method will be called repeatedly for all the config files in the
        config directory. To provide a better UX, we differentiate the error
        handling in this case (versus when the user has asked for a single
        config file to be uploaded).

        """
        try:
            self.upload_config_to_database(file_name, account_name)
        except ValueError:
            # We've already given all the info we can in a message, so carry
            # on to the next one
            pass
        except Exception:
            # Some other error occurred relating to this specific config file
            # or account. Since we are trying to upload all the config files,
            # we'll continue and hide this exception. However, we tell the
            # user how to get more info about this error by re-running with
            # just the account at fault. When we run in single-account mode we
            # will NOT hide the exception.
            print(_('To get a more detailed information on this error, re-run '
                    'this command for the specific account, i.e.: '
                    'keystone-manage account_config_upload --account-name %s') %
                  account_name)
            pass

    def read_account_configs_from_files(self):
        """Read configs from file(s) and load into database.

        The command line parameters have already been parsed and the CONF
        command option will have been set. It is either set to the name of an
        explicit account, or it's None to indicate that we want all account
        config files.

        """
        account_name = CONF.command.account_name
        conf_dir = CONF.identity.account_config_dir
        if not os.path.exists(conf_dir):
            print(_('Unable to locate account config directory: %s') % conf_dir)
            raise ValueError

        if account_name:
            # Request is to upload the configs for just one account
            fname = ACCOUNT_CONF_FHEAD + account_name + ACCOUNT_CONF_FTAIL
            self.upload_config_to_database(
                os.path.join(conf_dir, fname), account_name)
            return

        # Request is to transfer all config files, so let's read all the
        # files in the config directory, and transfer those that match the
        # filename pattern of 'keystone.<account_name>.conf'
        for r, d, f in os.walk(conf_dir):
            for fname in f:
                if (fname.startswith(ACCOUNT_CONF_FHEAD) and
                        fname.endswith(ACCOUNT_CONF_FTAIL)):
                    if fname.count('.') >= 2:
                        self.upload_configs_to_database(
                            os.path.join(r, fname),
                            fname[len(ACCOUNT_CONF_FHEAD):
                                  -len(ACCOUNT_CONF_FTAIL)])
                    else:
                        LOG.warn(_LW('Ignoring file (%s) while scanning '
                                     'account config directory'), fname)

    def run(self):
        # First off, let's just check we can talk to the account database
        try:
            self.resource_manager.list_accounts(driver_hints.Hints())
        except Exception:
            # It is likely that there is some SQL or other backend error
            # related to set up
            print(_('Unable to access the keystone database, please check it '
                    'is configured correctly.'))
            raise

        try:
            self.valid_options()
            self.read_account_configs_from_files()
        except ValueError:
            # We will already have printed out a nice message, so indicate
            # to caller the non-success error code to be used.
            return 1


class AccountConfigUpload(BaseApp):
    """Upload the account specific configuration files to the database."""

    name = 'account_config_upload'

    @classmethod
    def add_argument_parser(cls, subparsers):
        parser = super(AccountConfigUpload, cls).add_argument_parser(subparsers)
        parser.add_argument('--all', default=False, action='store_true',
                            help='Upload contents of all account specific '
                                 'configuration files. Either use this option '
                                 'or use the --account-name option to choose a '
                                 'specific account.')
        parser.add_argument('--account-name', default=None,
                            help='Upload contents of the specific '
                                 'configuration file for the given account. '
                                 'Either use this option or use the --all '
                                 'option to upload contents for all accounts.')
        return parser

    @staticmethod
    def main():
        dcu = AccountConfigUploadFiles()
        status = dcu.run()
        if status is not None:
            exit(status)


class SamlIdentityProviderMetadata(BaseApp):
    """Generate Identity Provider metadata."""

    name = 'saml_idp_metadata'

    @staticmethod
    def main():
        # NOTE(marek-denis): Since federation is currently an extension import
        # corresponding modules only when they are really going to be used.
        from keystone.contrib.federation import idp
        metadata = idp.MetadataGenerator().generate_metadata()
        print(metadata.to_string())


CMDS = [
    DbSync,
    DbVersion,
    AccountConfigUpload,
    FernetRotate,
    FernetSetup,
    MappingPurge,
    PKISetup,
    SamlIdentityProviderMetadata,
    SSLSetup,
    TokenFlush,
]


def add_command_parsers(subparsers):
    for cmd in CMDS:
        cmd.add_argument_parser(subparsers)


command_opt = cfg.SubCommandOpt('command',
                                title='Commands',
                                help='Available commands',
                                handler=add_command_parsers)


def main(argv=None, config_files=None):
    CONF.register_cli_opt(command_opt)

    config.configure()
    sql.initialize()
    config.set_default_for_default_log_levels()

    CONF(args=argv[1:],
         project='keystone',
         version=pbr.version.VersionInfo('keystone').version_string(),
         usage='%(prog)s [' + '|'.join([cmd.name for cmd in CMDS]) + ']',
         default_config_files=config_files)
    config.setup_logging()
    CONF.command.cmd_class.main()
