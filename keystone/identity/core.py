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

"""Main entry point into the Identity service."""

import abc
import functools
import os
import uuid

from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils
import six

from keystone import clean
from keystone.common import cache
from keystone.common import dependency
from keystone.common import driver_hints
from keystone.common import manager
from keystone import config
from keystone import exception
from keystone.i18n import _, _LW
from keystone.identity.mapping_backends import mapping
from keystone import notifications

import datetime

CONF = cfg.CONF

LOG = log.getLogger(__name__)

MEMOIZE = cache.get_memoization_decorator(section='identity')

ACCOUNT_CONF_FHEAD = 'keystone.'
ACCOUNT_CONF_FTAIL = '.conf'


def filter_user(user_ref):
    """Filter out private items in a user dict.

    'password', 'tenants' and 'groups' are never returned.

    :returns: user_ref

    """
    if user_ref:
        user_ref = user_ref.copy()
        user_ref.pop('password', None)
        user_ref.pop('tenants', None)
        user_ref.pop('groups', None)
        user_ref.pop('accounts', None)
        try:
            user_ref['extra'].pop('password', None)
            user_ref['extra'].pop('tenants', None)
        except KeyError:
            pass
    return user_ref


@dependency.requires('account_config_api')
class AccountConfigs(dict):
    """Discover, store and provide access to account specific configs.

    The setup_account_drivers() call will be made via the wrapper from
    the first call to any driver function handled by this manager.

    Account specific configurations are only supported for the identity backend
    and the individual configurations are either specified in the resource
    database or in individual account configuration files, depending on the
    setting of the 'account_configurations_from_database' config option.

    The result will be that for each account with a specific configuration,
    this class will hold a reference to a ConfigOpts and driver object that
    the identity manager and driver can use.

    """
    configured = False
    driver = None
    _any_sql = False

    def _load_driver(self, account_config):
        return importutils.import_object(
            account_config['cfg'].identity.driver, account_config['cfg'])

    def _assert_no_more_than_one_sql_driver(self, account_id, new_config,
                                            config_file=None):
        """Ensure there is more than one sql driver.

        Check to see if the addition of the driver in this new config
        would cause there to now be more than one sql driver.

        If we are loading from configuration files, the config_file will hold
        the name of the file we have just loaded.

        """
        if (new_config['driver'].is_sql and
                (self.driver.is_sql or self._any_sql)):
            # The addition of this driver would cause us to have more than
            # one sql driver, so raise an exception.
            if not config_file:
                config_file = _('Database at /accounts/%s/config') % account_id
            raise exception.MultipleSQLDriversInConfig(source=config_file)
        self._any_sql = self._any_sql or new_config['driver'].is_sql

    def _load_config_from_file(self, resource_api, file_list, account_name):

        try:
            account_ref = resource_api.get_account_by_name(account_name)
        except exception.AccountNotFound:
            LOG.warning(
                _LW('Invalid account name (%s) found in config file name'),
                account_name)
            return

        # Create a new entry in the account config dict, which contains
        # a new instance of both the conf environment and driver using
        # options defined in this set of config files.  Later, when we
        # service calls via this Manager, we'll index via this account
        # config dict to make sure we call the right driver
        account_config = {}
        account_config['cfg'] = cfg.ConfigOpts()
        config.configure(conf=account_config['cfg'])
        account_config['cfg'](args=[], project='keystone',
                             default_config_files=file_list)
        account_config['driver'] = self._load_driver(account_config)
        self._assert_no_more_than_one_sql_driver(account_ref['id'],
                                                 account_config,
                                                 config_file=file_list)
        self[account_ref['id']] = account_config

    def _setup_account_drivers_from_files(self, standard_driver, resource_api):
        """Read the account specific configuration files and load the drivers.

        Account configuration files are stored in the account config directory,
        and must be named of the form:

        keystone.<account_name>.conf

        For each file, call the load config method where the account_name
        will be turned into a account_id and then:

        - Create a new config structure, adding in the specific additional
          options defined in this config file
        - Initialise a new instance of the required driver with this new config

        """
        conf_dir = CONF.identity.account_config_dir
        if not os.path.exists(conf_dir):
            LOG.warning(_LW('Unable to locate account config directory: %s'),
                        conf_dir)
            return

        for r, d, f in os.walk(conf_dir):
            for fname in f:
                if (fname.startswith(ACCOUNT_CONF_FHEAD) and
                        fname.endswith(ACCOUNT_CONF_FTAIL)):
                    if fname.count('.') >= 2:
                        self._load_config_from_file(
                            resource_api, [os.path.join(r, fname)],
                            fname[len(ACCOUNT_CONF_FHEAD):
                                  -len(ACCOUNT_CONF_FTAIL)])
                    else:
                        LOG.debug(('Ignoring file (%s) while scanning account '
                                   'config directory'),
                                  fname)

    def _load_config_from_database(self, account_id, specific_config):

        def _assert_not_sql_driver(account_id, new_config):
            """Ensure this is not an sql driver.

            Due to multi-threading safety concerns, we do not currently support
            the setting of a specific identity driver to sql via the Identity
            API.

            """
            if new_config['driver'].is_sql:
                reason = _('Account specific sql drivers are not supported via '
                           'the Identity API. One is specified in '
                           '/accounts/%s/config') % account_id
                raise exception.InvalidAccountConfig(reason=reason)

        account_config = {}
        account_config['cfg'] = cfg.ConfigOpts()
        config.configure(conf=account_config['cfg'])
        account_config['cfg'](args=[], project='keystone')

        # Override any options that have been passed in as specified in the
        # database.
        for group in specific_config:
            for option in specific_config[group]:
                account_config['cfg'].set_override(
                    option, specific_config[group][option], group)

        account_config['cfg_overrides'] = specific_config
        account_config['driver'] = self._load_driver(account_config)
        _assert_not_sql_driver(account_id, account_config)
        self[account_id] = account_config

    def _setup_account_drivers_from_database(self, standard_driver,
                                            resource_api):
        """Read account specific configuration from database and load drivers.

        Account configurations are stored in the account-config backend,
        so we go through each account to find those that have a specific config
        defined, and for those that do we:

        - Create a new config structure, overriding any specific options
          defined in the resource backend
        - Initialise a new instance of the required driver with this new config

        """
        for account in resource_api.list_accounts():
            account_config_options = (
                self.account_config_api.
                get_config_with_sensitive_info(account['id']))
            if account_config_options:
                self._load_config_from_database(account['id'],
                                                account_config_options)

    def setup_account_drivers(self, standard_driver, resource_api):
        # This is called by the api call wrapper
        self.configured = True
        self.driver = standard_driver

        if CONF.identity.account_configurations_from_database:
            self._setup_account_drivers_from_database(standard_driver,
                                                     resource_api)
        else:
            self._setup_account_drivers_from_files(standard_driver,
                                                  resource_api)

    def get_account_driver(self, account_id):
        self.check_config_and_reload_account_driver_if_required(account_id)
        if account_id in self:
            return self[account_id]['driver']

    def get_account_conf(self, account_id):
        self.check_config_and_reload_account_driver_if_required(account_id)
        if account_id in self:
            return self[account_id]['cfg']
        else:
            return CONF

    def reload_account_driver(self, account_id):
        # Only used to support unit tests that want to set
        # new config values.  This should only be called once
        # the accounts have been configured, since it relies on
        # the fact that the configuration files/database have already been
        # read.
        if self.configured:
            if account_id in self:
                self[account_id]['driver'] = (
                    self._load_driver(self[account_id]))
            else:
                # The standard driver
                self.driver = self.driver()

    def check_config_and_reload_account_driver_if_required(self, account_id):
        """Check for, and load, any new account specific config for this account.

        This is only supported for the database-stored account specific
        configuration.

        When the account specific drivers were set up, we stored away the
        specific config for this account that was available at that time. So we
        now read the current version and compare. While this might seem
        somewhat inefficient, the sensitive config call is cached, so should be
        light weight. More importantly, when the cache timeout is reached, we
        will get any config that has been updated from any other keystone
        process.

        This cache-timeout approach works for both multi-process and
        multi-threaded keystone configurations. In multi-threaded
        configurations, even though we might remove a driver object (that
        could be in use by another thread), this won't actually be thrown away
        until all references to it have been broken. When that other
        thread is released back and is restarted with another command to
        process, next time it accesses the driver it will pickup the new one.

        """
        if (not CONF.identity.account_specific_drivers_enabled or
                not CONF.identity.account_configurations_from_database):
            # If specific drivers are not enabled, then there is nothing to do.
            # If we are not storing the configurations in the database, then
            # we'll only re-read the account specific config files on startup
            # of keystone.
            return

        latest_account_config = (
            self.account_config_api.
            get_config_with_sensitive_info(account_id))
        account_config_in_use = account_id in self

        if latest_account_config:
            if (not account_config_in_use or
                    latest_account_config != self[account_id]['cfg_overrides']):
                self._load_config_from_database(account_id,
                                                latest_account_config)
        elif account_config_in_use:
            # The account specific config has been deleted, so should remove the
            # specific driver for this account.
            try:
                del self[account_id]
            except KeyError:
                # Allow this error in case we are unlucky and in a
                # multi-threaded situation, two threads happen to be running
                # in lock step.
                pass
        # If we fall into the else condition, this means there is no account
        # config set, and there is none in use either, so we have nothing
        # to do.


def accounts_configured(f):
    """Wraps API calls to lazy load account configs after init.

    This is required since the assignment manager needs to be initialized
    before this manager, and yet this manager's init wants to be
    able to make assignment calls (to build the account configs).  So
    instead, we check if the accounts have been initialized on entry
    to each call, and if requires load them,

    """
    @functools.wraps(f)
    def wrapper(self, *args, **kwargs):
        if (not self.account_configs.configured and
                CONF.identity.account_specific_drivers_enabled):
            self.account_configs.setup_account_drivers(
                self.driver, self.resource_api)
        return f(self, *args, **kwargs)
    return wrapper


def exception_translated(exception_type):
    """Wraps API calls to map to correct exception."""

    def _exception_translated(f):
        @functools.wraps(f)
        def wrapper(self, *args, **kwargs):
            try:
                return f(self, *args, **kwargs)
            except exception.PublicIDNotFound as e:
                if exception_type == 'user':
                    raise exception.UserNotFound(user_id=str(e))
                elif exception_type == 'group':
                    raise exception.GroupNotFound(group_id=str(e))
                elif exception_type == 'assertion':
                    raise AssertionError(_('Invalid user / password'))
                else:
                    raise
        return wrapper
    return _exception_translated


@dependency.provider('identity_api')
@dependency.requires('assignment_api', 'credential_api', 'id_mapping_api',
                     'resource_api', 'revoke_api', 'jio_policy_api', 'preauth_api')
class Manager(manager.Manager):
    """Default pivot point for the Identity backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    This class also handles the support of account specific backends, by using
    the AccountConfigs class. The setup call for AccountConfigs is called
    from with the @accounts_configured wrapper in a lazy loading fashion
    to get around the fact that we can't satisfy the assignment api it needs
    from within our __init__() function since the assignment driver is not
    itself yet initialized.

    Each of the identity calls are pre-processed here to choose, based on
    account, which of the drivers should be called. The non-account-specific
    driver is still in place, and is used if there is no specific driver for
    the account in question (or we are not using multiple account drivers).

    Starting with Juno, in order to be able to obtain the account from
    just an ID being presented as part of an API call, a public ID to account
    and local ID mapping is maintained.  This mapping also allows for the local
    ID of drivers that do not provide simple UUIDs (such as LDAP) to be
    referenced via a public facing ID.  The mapping itself is automatically
    generated as entities are accessed via the driver.

    This mapping is only used when:
    - the entity is being handled by anything other than the default driver, or
    - the entity is being handled by the default LDAP driver and backward
    compatible IDs are not required.

    This means that in the standard case of a single SQL backend or the default
    settings of a single LDAP backend (since backward compatible IDs is set to
    True by default), no mapping is used. An alternative approach would be to
    always use the mapping table, but in the cases where we don't need it to
    make the public and local IDs the same. It is felt that not using the
    mapping by default is a more prudent way to introduce this functionality.

    """
    _USER = 'user'
    _GROUP = 'group'

    def __init__(self):
        super(Manager, self).__init__(CONF.identity.driver)
        self.account_configs = AccountConfigs()

        self.event_callbacks = {
            notifications.ACTIONS.deleted: {
                'account': [self._account_deleted],
            },
        }

    def _account_deleted(self, service, resource_type, operation,
                        payload):
        account_id = payload['resource_info']

        user_refs = self.list_users(account_scope=account_id)
        group_refs = self.list_groups(account_scope=account_id)

        for group in group_refs:
            # Cleanup any existing groups.
            try:
                self.delete_group(group['id'])
            except exception.GroupNotFound:
                LOG.debug(('Group %(groupid)s not found when deleting account '
                           'contents for %(accountid)s, continuing with '
                           'cleanup.'),
                          {'groupid': group['id'], 'accountid': account_id})

        # And finally, delete the users themselves
        for user in user_refs:
            try:
                self.delete_user(user['id'])
            except exception.UserNotFound:
                LOG.debug(('User %(userid)s not found when deleting account '
                           'contents for %(accountid)s, continuing with '
                           'cleanup.'),
                          {'userid': user['id'], 'accountid': account_id})

    # Account ID normalization methods

    def _set_account_id_and_mapping(self, ref, account_id, driver,
                                   entity_type):
        """Patch the account_id/public_id into the resulting entity(ies).

        :param ref: the entity or list of entities to post process
        :param account_id: the account scope used for the call
        :param driver: the driver used to execute the call
        :param entity_type: whether this is a user or group

        :returns: post processed entity or list or entities

        Called to post-process the entity being returned, using a mapping
        to substitute a public facing ID as necessary. This method must
        take into account:

        - If the driver is not account aware, then we must set the account
          attribute of all entities irrespective of mapping.
        - If the driver does not support UUIDs, then we always want to provide
          a mapping, except for the special case of this being the default
          driver and backward_compatible_ids is set to True. This is to ensure
          that entity IDs do not change for an existing LDAP installation (only
          single account/driver LDAP configurations were previously supported).
        - If the driver does support UUIDs, then we always create a mapping
          entry, but use the local UUID as the public ID.  The exception to
        - this is that if we just have single driver (i.e. not using specific
          multi-account configs), then we don't both with the mapping at all.

        """
        conf = CONF.identity

        if not self._needs_post_processing(driver):
            # a classic case would be when running with a single SQL driver
            return ref

        LOG.debug('ID Mapping - Account ID: %(account)s, '
                  'Default Driver: %(driver)s, '
                  'Accounts: %(aware)s, UUIDs: %(generate)s, '
                  'Compatible IDs: %(compat)s',
                  {'account': account_id,
                   'driver': (driver == self.driver),
                   'aware': driver.is_account_aware(),
                   'generate': driver.generates_uuids(),
                   'compat': CONF.identity_mapping.backward_compatible_ids})

        if isinstance(ref, dict):
            return self._set_account_id_and_mapping_for_single_ref(
                ref, account_id, driver, entity_type, conf)
        elif isinstance(ref, list):
            return [self._set_account_id_and_mapping(
                    x, account_id, driver, entity_type) for x in ref]
        else:
            raise ValueError(_('Expected dict or list: %s') % type(ref))

    def _needs_post_processing(self, driver):
        """Returns whether entity from driver needs account added or mapping."""
        return (driver is not self.driver or not driver.generates_uuids() or
                not driver.is_account_aware())

    def _set_account_id_and_mapping_for_single_ref(self, ref, account_id,
                                                  driver, entity_type, conf):
        LOG.debug('Local ID: %s', ref['id'])
        ref = ref.copy()

        self._insert_account_id_if_needed(ref, driver, account_id, conf)

        if self._is_mapping_needed(driver):
            local_entity = {'account_id': ref['account_id'],
                            'local_id': ref['id'],
                            'entity_type': entity_type}
            public_id = self.id_mapping_api.get_public_id(local_entity)
            if public_id:
                ref['id'] = public_id
                LOG.debug('Found existing mapping to public ID: %s',
                          ref['id'])
            else:
                # Need to create a mapping. If the driver generates UUIDs
                # then pass the local UUID in as the public ID to use.
                if driver.generates_uuids():
                    public_id = ref['id']
                ref['id'] = self.id_mapping_api.create_id_mapping(
                    local_entity, public_id)
                LOG.debug('Created new mapping to public ID: %s',
                          ref['id'])
        return ref

    def _insert_account_id_if_needed(self, ref, driver, account_id, conf):
        """Inserts the account ID into the ref, if required.

        If the driver can't handle accounts, then we need to insert the
        account_id into the entity being returned.  If the account_id is
        None that means we are running in a single backend mode, so to
        remain backwardly compatible, we put in the default account ID.
        """
        if not driver.is_account_aware():
            if account_id is None:
                account_id = conf.default_account_id
            ref['account_id'] = account_id

    def _is_mapping_needed(self, driver):
        """Returns whether mapping is needed.

        There are two situations where we must use the mapping:
        - this isn't the default driver (i.e. multiple backends), or
        - we have a single backend that doesn't use UUIDs
        The exception to the above is that we must honor backward
        compatibility if this is the default driver (e.g. to support
        current LDAP)
        """
        is_not_default_driver = driver is not self.driver
        return (is_not_default_driver or (
            not driver.generates_uuids() and
            not CONF.identity_mapping.backward_compatible_ids))

    def _clear_account_id_if_account_unaware(self, driver, ref):
        """Clear account_id details if driver is not account aware."""
        if not driver.is_account_aware() and 'account_id' in ref:
            ref = ref.copy()
            ref.pop('account_id')
        return ref

    def _select_identity_driver(self, account_id):
        """Choose a backend driver for the given account_id.

        :param account_id: The account_id for which we want to find a driver.  If
                          the account_id is specified as None, then this means
                          we need a driver that handles multiple accounts.

        :returns: chosen backend driver

        If there is a specific driver defined for this account then choose it.
        If the account is None, or there no specific backend for the given
        account is found, then we chose the default driver.

        """
        if account_id is None:
            driver = self.driver
        else:
            driver = (self.account_configs.get_account_driver(account_id) or
                      self.driver)

        # If the driver is not account aware (e.g. LDAP) then check to
        # ensure we are not mapping multiple accounts onto it - the only way
        # that would happen is that the default driver is LDAP and the
        # account is anything other than None or the default account.
        if (not driver.is_account_aware() and driver == self.driver and
            account_id != CONF.identity.default_account_id and
                account_id is not None):
                    LOG.warning('Found multiple accounts being mapped to a '
                                'driver that does not support that (e.g. '
                                'LDAP) - Account ID: %(account)s, '
                                'Default Driver: %(driver)s',
                                {'account': account_id,
                                 'driver': (driver == self.driver)})
                    raise exception.AccountNotFound(account_id=account_id)
        return driver

    def _get_account_driver_and_entity_id(self, public_id):
        """Look up details using the public ID.

        :param public_id: the ID provided in the call

        :returns: account_id, which can be None to indicate that the driver
                  in question supports multiple accounts
                  driver selected based on this account
                  entity_id which will is understood by the driver.

        Use the mapping table to look up the account, driver and local entity
        that is represented by the provided public ID.  Handle the situations
        were we do not use the mapping (e.g. single driver that understands
        UUIDs etc.)

        """
        conf = CONF.identity
        # First, since we don't know anything about the entity yet, we must
        # assume it needs mapping, so long as we are using account specific
        # drivers.
        if conf.account_specific_drivers_enabled:
            local_id_ref = self.id_mapping_api.get_id_mapping(public_id)
            if local_id_ref:
                return (
                    local_id_ref['account_id'],
                    self._select_identity_driver(local_id_ref['account_id']),
                    local_id_ref['local_id'])

        # So either we are using multiple drivers but the public ID is invalid
        # (and hence was not found in the mapping table), or the public ID is
        # being handled by the default driver.  Either way, the only place left
        # to look is in that standard driver. However, we don't yet know if
        # this driver also needs mapping (e.g. LDAP in non backward
        # compatibility mode).
        driver = self.driver
        if driver.generates_uuids():
            if driver.is_account_aware:
                # No mapping required, and the driver can handle the account
                # information itself.  The classic case of this is the
                # current SQL driver.
                return (None, driver, public_id)
            else:
                # Although we don't have any drivers of this type, i.e. that
                # understand UUIDs but not accounts, conceptually you could.
                return (conf.default_account_id, driver, public_id)

        # So the only place left to find the ID is in the default driver which
        # we now know doesn't generate UUIDs
        if not CONF.identity_mapping.backward_compatible_ids:
            # We are not running in backward compatibility mode, so we
            # must use a mapping.
            local_id_ref = self.id_mapping_api.get_id_mapping(public_id)
            if local_id_ref:
                return (
                    local_id_ref['account_id'],
                    driver,
                    local_id_ref['local_id'])
            else:
                raise exception.PublicIDNotFound(id=public_id)

        # If we reach here, this means that the default driver
        # requires no mapping - but also doesn't understand accounts
        # (e.g. the classic single LDAP driver situation). Hence we pass
        # back the public_ID unmodified and use the default account (to
        # keep backwards compatibility with existing installations).
        #
        # It is still possible that the public ID is just invalid in
        # which case we leave this to the caller to check.
        return (conf.default_account_id, driver, public_id)

    def _assert_user_and_group_in_same_backend(
            self, user_entity_id, user_driver, group_entity_id, group_driver):
        """Ensures that user and group IDs are backed by the same backend.

        Raise a CrossBackendNotAllowed exception if they are not from the same
        backend, otherwise return None.

        """
        if user_driver is not group_driver:
            # Determine first if either IDs don't exist by calling
            # the driver.get methods (which will raise a NotFound
            # exception).
            user_driver.get_user(user_entity_id)
            group_driver.get_group(group_entity_id)
            # If we get here, then someone is attempting to create a cross
            # backend membership, which is not allowed.
            raise exception.CrossBackendNotAllowed(group_id=group_entity_id,
                                                   user_id=user_entity_id)

    def _mark_account_id_filter_satisfied(self, hints):
        if hints:
            for filter in hints.filters:
                if (filter['name'] == 'account_id' and
                        filter['comparator'] == 'equals'):
                    hints.filters.remove(filter)

    def _ensure_account_id_in_hints(self, hints, account_id):
        if (account_id is not None and
                not hints.get_exact_filter_by_name('account_id')):
            hints.add_filter('account_id', account_id)

    # The actual driver calls - these are pre/post processed here as
    # part of the Manager layer to make sure we:
    #
    # - select the right driver for this account
    # - clear/set account_ids for drivers that do not support accounts
    # - create any ID mapping that might be required

    @notifications.emit_event('authenticate')
    @accounts_configured
    @exception_translated('assertion')
    def authenticate(self, context, user_id, password):
        account_id, driver, entity_id = (
            self._get_account_driver_and_entity_id(user_id))
        ref = driver.authenticate(entity_id, password)
        return self._set_account_id_and_mapping(
            ref, account_id, driver, mapping.EntityType.USER)

    @accounts_configured
    @exception_translated('user')
    def create_user(self, user_ref, initiator=None):
        user = user_ref.copy()
        user['name'] = clean.user_name(user['name'])
        user.setdefault('enabled', True)
        user['enabled'] = clean.user_enabled(user['enabled'])
        account_id = user['account_id']
        self.resource_api.get_account(account_id)

        # For creating a user, the account is in the object itself
        account_id = user_ref['account_id']
        driver = self._select_identity_driver(account_id)
        user = self._clear_account_id_if_account_unaware(driver, user)
        # Generate a local ID - in the future this might become a function of
        # the underlying driver so that it could conform to rules set down by
        # that particular driver type.
        user['id'] = user_ref.get('id', uuid.uuid4().hex)
        ref = driver.create_user(user['id'], user)
        notifications.Audit.created(self._USER, user['id'], initiator)
        return self._set_account_id_and_mapping(
            ref, account_id, driver, mapping.EntityType.USER)

    @accounts_configured
    @exception_translated('user')
    @MEMOIZE
    def get_user(self, user_id):
        account_id, driver, entity_id = (
            self._get_account_driver_and_entity_id(user_id))
        ref = driver.get_user(entity_id)
        return self._set_account_id_and_mapping(
            ref, account_id, driver, mapping.EntityType.USER)

    @accounts_configured
    @exception_translated('user')
    @MEMOIZE
    def get_unfiltered_user(self, user_id):
        account_id, driver, entity_id = (
            self._get_account_driver_and_entity_id(user_id))
        ref = driver.get_unfiltered_user(entity_id)
        return ref

    @accounts_configured
    @exception_translated('user')
    @MEMOIZE
    def get_root_user(self, account_id):
        driver = self._select_identity_driver(account_id)
        ref = driver.get_root_user(account_id)
        return self._set_account_id_and_mapping(
            ref, account_id, driver, mapping.EntityType.USER)

    def assert_user_enabled(self, user_id, user=None):
        """Assert the user and the user's account are enabled.

        :raise AssertionError if the user or the user's account is disabled.
        """
        if user is None:
            user = self.get_user(user_id)
        self.resource_api.assert_account_enabled(user['account_id'])
        if not user.get('enabled', True):
            raise AssertionError(_('User is disabled: %s') % user_id)

    @accounts_configured
    @exception_translated('user')
    @MEMOIZE
    def get_user_by_name(self, user_name, account_id):
        driver = self._select_identity_driver(account_id)
        ref = driver.get_user_by_name(user_name, account_id)
        return self._set_account_id_and_mapping(
            ref, account_id, driver, mapping.EntityType.USER)

    def get_account_if_name_root(self, user_name):
        driver = self._select_identity_driver(None)
        return driver.get_account_if_name_root(user_name)

    @manager.response_truncated
    @accounts_configured
    @exception_translated('user')
    def list_users(self, account_id, account_scope=None, hints=None):
        driver = self._select_identity_driver(account_scope)
        hints = hints or driver_hints.Hints()
        if driver.is_account_aware():
            # Force the account_scope into the hint to ensure that we only get
            # back accounts for that scope.
            self._ensure_account_id_in_hints(hints, account_scope)
        else:
            # We are effectively satisfying any account_id filter by the above
            # driver selection, so remove any such filter.
            self._mark_account_id_filter_satisfied(hints)
        ref_list = driver.list_users(hints, account_id)
        return self._set_account_id_and_mapping(
            ref_list, account_scope, driver, mapping.EntityType.USER)

    @MEMOIZE
    def get_users_count_in_account(self, account_id):
        driver = self._select_identity_driver(None)
        return driver.get_users_count_in_account(account_id)

    @accounts_configured
    @exception_translated('group')
    @MEMOIZE
    def get_user_summary_for_group(self, group_id):
        account_id, driver, entity_id = (
            self._get_account_driver_and_entity_id(group_id))
        ref = driver.get_user_summary_for_group(entity_id)
        return self._set_account_id_and_mapping(
            ref, account_id, driver, mapping.EntityType.GROUP)

    @accounts_configured
    @exception_translated('user')
    @MEMOIZE
    def get_group_summary_for_user(self, user_id):
        account_id, driver, entity_id = (
            self._get_account_driver_and_entity_id(user_id))
        ref = driver.get_group_summary_for_user(entity_id)
        return self._set_account_id_and_mapping(
            ref, account_id, driver, mapping.EntityType.USER)

    @accounts_configured
    @exception_translated('user')
    def update_user(self, user_id, user_ref, initiator=None):
        old_user_ref = self.get_unfiltered_user(user_id)
        user = user_ref.copy()
        if 'name' in user:
            user['name'] = clean.user_name(user['name'])
        if 'enabled' in user:
            user['enabled'] = clean.user_enabled(user['enabled'])
        if 'account_id' in user:
            self.resource_api.get_account(user['account_id'])
        if 'id' in user:
            if user_id != user['id']:
                raise exception.ValidationError(_('Cannot change user ID'))
            # Since any ID in the user dict is now irrelevant, remove its so as
            # the driver layer won't be confused by the fact the this is the
            # public ID not the local ID
            user.pop('id')
        if 'password' in user:
            if user['password'] is None:
                if old_user_ref.get('type') == 'root':
                    raise exception.Forbidden('Password cannot be removed for root user.')
                user['expiry'] = None
            else:
                expiry_days = CONF.password_policy.expiry_days
                if expiry_days is not None:
                    user['expiry'] = datetime.datetime.utcnow() + datetime.timedelta(days=expiry_days)

        account_id, driver, entity_id = (
            self._get_account_driver_and_entity_id(user_id))
        user = self._clear_account_id_if_account_unaware(driver, user)
        self.get_user.invalidate(self, old_user_ref['id'])
        self.get_user_by_name.invalidate(self, old_user_ref['name'],
                                         old_user_ref['account_id'])

        ref = driver.update_user(entity_id, user)

        notifications.Audit.updated(self._USER, user_id, initiator)

        enabled_change = ((user.get('enabled') is False) and
                          user['enabled'] != old_user_ref.get('enabled'))
        if enabled_change or user.get('password') is not None:
            self.emit_invalidate_user_token_persistence(user_id)

        if user_ref.get('password') is not None:
            self.update_user_history(old_user_ref.get('id'), user_ref.get('password'), CONF.password_policy.num_password_saved, False)

        return self._set_account_id_and_mapping(
            ref, account_id, driver, mapping.EntityType.USER)

    @accounts_configured
    @exception_translated('user')
    def delete_user(self, user_id, initiator=None):
        account_id, driver, entity_id = (
            self._get_account_driver_and_entity_id(user_id))
        # Get user details to invalidate the cache.
        user_old = self.get_user(user_id)
        driver.remove_user_membership(user_id)
        self.preauth_api.delete_user_preauth_token(user_id)
        driver.delete_user(entity_id)
        self.assignment_api.delete_user(user_id)
        self.get_user.invalidate(self, user_id)
        self.get_user_by_name.invalidate(self, user_old['name'],
                                         user_old['account_id'])
        self.credential_api.delete_credentials_for_user(user_id)
        self.id_mapping_api.delete_id_mapping(user_id)
        self.jio_policy_api.detach_user_policy(user_id)
        notifications.Audit.deleted(self._USER, user_id, initiator)

    @accounts_configured
    @exception_translated('group')
    def create_group(self, group_ref, initiator=None):
        group = group_ref.copy()
        group.setdefault('description', '')
        account_id = group['account_id']
        self.resource_api.get_account(account_id)

        # For creating a group, the account is in the object itself
        account_id = group_ref['account_id']
        driver = self._select_identity_driver(account_id)
        group = self._clear_account_id_if_account_unaware(driver, group)
        # Generate a local ID - in the future this might become a function of
        # the underlying driver so that it could conform to rules set down by
        # that particular driver type.
        group['id'] = uuid.uuid4().hex
        ref = driver.create_group(group['id'], group)

        notifications.Audit.created(self._GROUP, group['id'], initiator)

        return self._set_account_id_and_mapping(
            ref, account_id, driver, mapping.EntityType.GROUP)

    @accounts_configured
    @exception_translated('group')
    @MEMOIZE
    def get_group(self, group_id):
        account_id, driver, entity_id = (
            self._get_account_driver_and_entity_id(group_id))
        ref = driver.get_group(entity_id)
        return self._set_account_id_and_mapping(
            ref, account_id, driver, mapping.EntityType.GROUP)

    @accounts_configured
    @exception_translated('group')
    def get_group_by_name(self, group_name, account_id):
        driver = self._select_identity_driver(account_id)
        ref = driver.get_group_by_name(group_name, account_id)
        return self._set_account_id_and_mapping(
            ref, account_id, driver, mapping.EntityType.GROUP)

    @accounts_configured
    @exception_translated('group')
    def update_group(self, group_id, group, initiator=None):
        if 'account_id' in group:
            self.resource_api.get_account(group['account_id'])
        account_id, driver, entity_id = (
            self._get_account_driver_and_entity_id(group_id))
        group = self._clear_account_id_if_account_unaware(driver, group)
        ref = driver.update_group(entity_id, group)
        self.get_group.invalidate(self, group_id)
        notifications.Audit.updated(self._GROUP, group_id, initiator)
        return self._set_account_id_and_mapping(
            ref, account_id, driver, mapping.EntityType.GROUP)

    @accounts_configured
    @exception_translated('group')
    def delete_group(self, group_id, initiator=None):
        account_id, driver, entity_id = (
            self._get_account_driver_and_entity_id(group_id))
        user_ids = (u['id'] for u in self.list_users_in_group(group_id))
        driver.delete_group(entity_id)
        driver.remove_group_membership(group_id)
        self.get_group.invalidate(self, group_id)
        self.id_mapping_api.delete_id_mapping(group_id)
        self.assignment_api.delete_group(group_id)
        self.jio_policy_api.detach_group_policy(group_id)

        notifications.Audit.deleted(self._GROUP, group_id, initiator)

        for uid in user_ids:
            self.emit_invalidate_user_token_persistence(uid)

    @accounts_configured
    @exception_translated('group')
    def add_user_to_group(self, user_id, group_id):
        @exception_translated('user')
        def get_entity_info_for_user(public_id):
            return self._get_account_driver_and_entity_id(public_id)

        _account_id, group_driver, group_entity_id = (
            self._get_account_driver_and_entity_id(group_id))
        # Get the same info for the user_id, taking care to map any
        # exceptions correctly
        _account_id, user_driver, user_entity_id = (
            get_entity_info_for_user(user_id))

        self._assert_user_and_group_in_same_backend(
            user_entity_id, user_driver, group_entity_id, group_driver)

        group_driver.add_user_to_group(user_entity_id, group_entity_id)

    @accounts_configured
    @exception_translated('group')
    def remove_user_from_group(self, user_id, group_id):
        @exception_translated('user')
        def get_entity_info_for_user(public_id):
            return self._get_account_driver_and_entity_id(public_id)

        _account_id, group_driver, group_entity_id = (
            self._get_account_driver_and_entity_id(group_id))
        # Get the same info for the user_id, taking care to map any
        # exceptions correctly
        _account_id, user_driver, user_entity_id = (
            get_entity_info_for_user(user_id))

        self._assert_user_and_group_in_same_backend(
            user_entity_id, user_driver, group_entity_id, group_driver)

        group_driver.remove_user_from_group(user_entity_id, group_entity_id)
        self.emit_invalidate_user_token_persistence(user_id)

    @notifications.internal(notifications.INVALIDATE_USER_TOKEN_PERSISTENCE)
    def emit_invalidate_user_token_persistence(self, user_id):
        """Emit a notification to the callback system to revoke user tokens.

        This method and associated callback listener removes the need for
        making a direct call to another manager to delete and revoke tokens.

        :param user_id: user identifier
        :type user_id: string
        """
        pass

    @notifications.internal(
        notifications.INVALIDATE_USER_PROJECT_TOKEN_PERSISTENCE)
    def emit_invalidate_grant_token_persistence(self, user_project):
        """Emit a notification to the callback system to revoke grant tokens.

        This method and associated callback listener removes the need for
        making a direct call to another manager to delete and revoke tokens.

        :param user_project: {'user_id': user_id, 'project_id': project_id}
        :type user_project: dict
        """
        pass

    @manager.response_truncated
    @accounts_configured
    @exception_translated('user')
    def list_groups_for_user(self, user_id, hints=None):
        account_id, driver, entity_id = (
            self._get_account_driver_and_entity_id(user_id))
        hints = hints or driver_hints.Hints()
        if not driver.is_account_aware():
            # We are effectively satisfying any account_id filter by the above
            # driver selection, so remove any such filter
            self._mark_account_id_filter_satisfied(hints)
        ref_list = driver.list_groups_for_user(entity_id, hints)
        return self._set_account_id_and_mapping(
            ref_list, account_id, driver, mapping.EntityType.GROUP)

    @manager.response_truncated
    @accounts_configured
    @exception_translated('group')
    def list_groups(self, account_id, account_scope=None, hints=None):
        driver = self._select_identity_driver(account_scope)
        hints = hints or driver_hints.Hints()
        if driver.is_account_aware():
            # Force the account_scope into the hint to ensure that we only get
            # back accounts for that scope.
            self._ensure_account_id_in_hints(hints, account_scope)
        else:
            # We are effectively satisfying any account_id filter by the above
            # driver selection, so remove any such filter.
            self._mark_account_id_filter_satisfied(hints)
        ref_list = driver.list_groups(hints, account_id)
        return self._set_account_id_and_mapping(
            ref_list, account_scope, driver, mapping.EntityType.GROUP)


    @manager.response_truncated
    @accounts_configured
    @exception_translated('group')
    def list_users_in_group(self, group_id, hints=None):
        account_id, driver, entity_id = (
            self._get_account_driver_and_entity_id(group_id))
        hints = hints or driver_hints.Hints()
        if not driver.is_account_aware():
            # We are effectively satisfying any account_id filter by the above
            # driver selection, so remove any such filter
            self._mark_account_id_filter_satisfied(hints)
        ref_list = driver.list_users_in_group(entity_id, hints)
        return self._set_account_id_and_mapping(
            ref_list, account_id, driver, mapping.EntityType.USER)

    @accounts_configured
    @exception_translated('group')
    def check_user_in_group(self, user_id, group_id):
        @exception_translated('user')
        def get_entity_info_for_user(public_id):
            return self._get_account_driver_and_entity_id(public_id)

        _account_id, group_driver, group_entity_id = (
            self._get_account_driver_and_entity_id(group_id))
        # Get the same info for the user_id, taking care to map any
        # exceptions correctly
        _account_id, user_driver, user_entity_id = (
            get_entity_info_for_user(user_id))

        self._assert_user_and_group_in_same_backend(
            user_entity_id, user_driver, group_entity_id, group_driver)

        return group_driver.check_user_in_group(user_entity_id,
                                                group_entity_id)

    @accounts_configured
    def get_user_history(self, user_id):
        account_id, driver, entity_id = (
            self._get_account_driver_and_entity_id(user_id))
        return driver.get_user_history(user_id, CONF.password_policy.num_password_saved)

    def update_user_history(self, user_id, original_password, count, hashed=False):
        account_id, driver, entity_id = (
            self._get_account_driver_and_entity_id(user_id))
        driver.update_user_history(user_id, original_password, count, hashed)

    def reset_password(self, context, account_id, password):
        user = self.get_root_user(account_id)
        user_id = user.get('id')
        update_dict = {'password': password}
        self.update_user(user_id, update_dict)

    @accounts_configured
    def change_password(self, context, user_id, original_password,
                        new_password):

        # authenticate() will raise an AssertionError if authentication fails
        self.authenticate(context, user_id, original_password)

        update_dict = {'password': new_password}
        self.update_user(user_id, update_dict)

    @MEMOIZE
    def get_groups_count_in_account(self, account_id):
        driver = self._select_identity_driver(account_id)
        return driver.get_groups_count_in_account(account_id)

    def get_group_users_count_in_account(self, group_id):
        driver = self._select_identity_driver(None)
        return driver.get_group_users_count_in_account(group_id)

    def get_user_assign_group_count(self, user_id):
        driver = self._select_identity_driver(None)
        return driver.get_user_assign_group_count(user_id)


@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for an Identity driver."""

    def _get_list_limit(self):
        return CONF.identity.list_limit or CONF.list_limit

    def is_account_aware(self):
        """Indicates if Driver supports accounts."""
        return True

    @property
    def is_sql(self):
        """Indicates if this Driver uses SQL."""
        return False

    @property
    def multiple_accounts_supported(self):
        return (self.is_account_aware() or
                CONF.identity.account_specific_drivers_enabled)

    def generates_uuids(self):
        """Indicates if Driver generates UUIDs as the local entity ID."""
        return True

    @abc.abstractmethod
    def authenticate(self, user_id, password):
        """Authenticate a given user and password.
        :returns: user_ref
        :raises: AssertionError
        """
        raise exception.NotImplemented()  # pragma: no cover

    # user crud

    @abc.abstractmethod
    def create_user(self, user_id, user):
        """Creates a new user.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_users(self, hints):
        """List users in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of user_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_users_count_in_account(self, account_id):
        """ Gets total user count

            in an account
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_users_in_group(self, group_id, hints):
        """List users in a group.

        :param group_id: the group in question
        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of user_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_user(self, user_id):
        """Get a user by ID.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_group_summary_for_user(self, user_id):
        """Get a user by ID.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover
    @abc.abstractmethod
    def update_user(self, user_id, user):
        """Updates an existing user.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def add_user_to_group(self, user_id, group_id):
        """Adds a user to a group.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def check_user_in_group(self, user_id, group_id):
        """Checks if a user is a member of a group.

        :raises: keystone.exception.UserNotFound,
                 keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def remove_user_from_group(self, user_id, group_id):
        """Removes a user from a group.

        :raises: keystone.exception.NotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_user(self, user_id):
        """Deletes an existing user.

        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_user_by_name(self, user_name, account_id):
        """Get a user by name.

        :returns: user_ref
        :raises: keystone.exception.UserNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    # group crud

    @abc.abstractmethod
    def create_group(self, group_id, group):
        """Creates a new group.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_groups(self, hints):
        """List groups in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of group_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_groups_for_user(self, user_id, hints):
        """List groups a user is in

        :param user_id: the user in question
        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of group_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_group(self, group_id):
        """Get a group by ID.

        :returns: group_ref
        :raises: keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_group_by_name(self, group_name, account_id):
        """Get a group by name.

        :returns: group_ref
        :raises: keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_group(self, group_id, group):
        """Updates an existing group.

        :raises: keystone.exceptionGroupNotFound,
                 keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_group(self, group_id):
        """Deletes an existing group.

        :raises: keystone.exception.GroupNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_groups_count_in_account(self, account_id):
        """
        Get the group count in account
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_group_users_count_in_account(self, group_id):
        """
        Get the user count in the group
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_user_assign_group_count(self, user_id):
        """
        Get the group count user is assigned to
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_user_history(self, user_id, original_password, count, hashed=False):
        raise exception.NotImplemented()

    # end of identity


@dependency.provider('id_mapping_api')
class MappingManager(manager.Manager):
    """Default pivot point for the ID Mapping backend."""

    def __init__(self):
        super(MappingManager, self).__init__(CONF.identity_mapping.driver)


@six.add_metaclass(abc.ABCMeta)
class MappingDriver(object):
    """Interface description for an ID Mapping driver."""

    @abc.abstractmethod
    def get_public_id(self, local_entity):
        """Returns the public ID for the given local entity.

        :param dict local_entity: Containing the entity account, local ID and
                                  type ('user' or 'group').
        :returns: public ID, or None if no mapping is found.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_id_mapping(self, public_id):
        """Returns the local mapping.

        :param public_id: The public ID for the mapping required.
        :returns dict: Containing the entity account, local ID and type. If no
                       mapping is found, it returns None.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_id_mapping(self, local_entity, public_id=None):
        """Create and store a mapping to a public_id.

        :param dict local_entity: Containing the entity account, local ID and
                                  type ('user' or 'group').
        :param public_id: If specified, this will be the public ID.  If this
                          is not specified, a public ID will be generated.
        :returns: public ID

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_id_mapping(self, public_id):
        """Deletes an entry for the given public_id.

        :param public_id: The public ID for the mapping to be deleted.

        The method is silent if no mapping is found.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def purge_mappings(self, purge_filter):
        """Purge selected identity mappings.

        :param dict purge_filter: Containing the attributes of the filter that
                                  defines which entries to purge. An empty
                                  filter means purge all mappings.

        """
        raise exception.NotImplemented()  # pragma: no cover
