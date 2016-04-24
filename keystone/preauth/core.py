import abc

from oslo_config import cfg
import six

from keystone.common import dependency
from keystone.common import manager
from keystone import exception

CONF = cfg.CONF

@dependency.requires('identity_api')
@dependency.provider('preauth_api')
class Manager(manager.Manager):

    _PREAUTH = 'preauth'

    def __init__(self):
        super(Manager, self).__init__(CONF.preauth.driver)

    def create_preauth_token(self, preauth_token):
        return self.driver.create_preauth_token(preauth_token)

    def get_preauth_token(self, token_id):
        return self.driver.get_preauth_token(token_id)

    def list_preauth_token_in_account(self, account_id):
        return self.driver.list_preauth_token_in_account(account_id)

    def list_preauth_token_of_user(self, user_id):
        return self.driver.list_preauth_token_of_user(user_id)

    def revoke_preauth_token(self, token_id, user_id):
        user = self.identity_api.get_user(user_id)
        preauth_token = self.driver.get_preauth_token(token_id)
        if user.get('type') != 'root':
            if preauth_token.get('user_id') != user_id:
                raise exception.Forbidden(message='Unauthorised to delete the preauth token')
        elif user.get('account_id') != preauth_token.get('account_id'):
                raise exception.Forbidden(message='Unauthorised to delete the preauth token')

        return self.driver.revoke_preauth_token(token_id)

    def get_user_from_token_id(self, token_id):
        user_id, account_id = self.driver.get_user_from_token_id(token_id)
        return user_id, account_id

    def is_preauth_token_valid(self, action, resource, object_id, token_id):
        return self.driver.is_preauth_token_valid(action,
                                                  resource,
                                                  object_id,
                                                  token_id)
    def delete_user_preauth_token(self, user_id):
        return self.driver.delete_user_preauth_token(user_id)

@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    def create_preauth_token(self, preauth_token):
        raise exception.NotImplemented()

    def get_preauth_token(self, token_id):
        raise exception.NotImplemented()

    def list_preauth_token_in_account(self, account_id):
        raise exception.NotImplemented()

    def list_preauth_token_of_user(self, user_id):
        raise exception.NotImplemented()

    def revoke_preauth_token(self, token_id, user_id):
        raise exception.NotImplemented()

    def get_user_from_token_id(self, token_id):
        raise exception.NotImplemented()

    def is_preauth_token_valid(self, action, resource, object_id, token_id):
        raise exception.NotImplemented()

    def delete_user_preauth_token(self, user_id):
        raise exception.NotImplemented()
