import uuid
from oslo_config import cfg
from oslo_log import log

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone import notifications
from keystone.jio_policy import schema
from keystone import exception
from keystone.common import wsgi
import datetime as datetime

LOG = log.getLogger(__name__)

@dependency.requires('preauth_api','jio_policy_api','identity_api')
class PreauthTokenV3(controller.V3Controller):
    collection_name = "preauth_token"
    member_name = "preauth_token"

    def create_preauth_token(self, context, **kwargs):
        preauth_token = {}
        try:
            action = kwargs['action']
            resource = kwargs['resource']
        except KeyError as e:
            raise exception.ValidationError(attribute=e,
                                            target="request body")

        if isinstance(action, list) or isinstance(resource, list):
            raise exception.ValidationError(attribute="single value",
                                  target="action and resource")

        try:
            preauth_token['user_id'] = context['environment']['KEYSTONE_AUTH_CONTEXT'][
                                        'user_id']
        except KeyError:
            raise exception.Forbidden('Cannot find user_id in context.')

        try:
            preauth_token['account_id']= context['environment']['KEYSTONE_AUTH_CONTEXT'][
                                        'account_id']
        except KeyError:
            raise exception.Forbidden('Cannot find account_id in context.')

        res_split = resource.split(':')
        if res_split[3] == '':
            res_split[3] = preauth_token['account_id']
        elif len(res_split[3]) > 12 :
            res_split[3] =res_split[3][-12:]

        if res_split[3] != preauth_token['account_id']:
            raise exception.Forbidden('Cannot create preauth token for another account resource.')

        resource = ':'.join(res_split)

        if 'duration' in kwargs:
            duration = int(kwargs.get('duration'))
            if duration < 1:
                raise exception.ValidationError(
                    attribute="positive integer",
                    target="duration")
            preauth_token['expires'] = datetime.datetime.utcnow() + datetime.timedelta(seconds=duration)
            LOG.debug('create_pre_auth_token for action: %s, resource: %s, duration: %s', action, resource, duration)
        else:
            LOG.debug('create_pre_auth_token for action: %s, resource: %s for infinite duration.', action, resource)

        is_authorized =  self.jio_policy_api.is_user_authorized(preauth_token['user_id'], preauth_token['account_id'], action, resource, False)
        if not is_authorized:
            raise exception.Forbidden(
                message='Policy does not allow to perform this action')

        preauth_token['object_id'] = kwargs.get('object_id', None)
        if preauth_token['object_id'] == '':
            raise exception.ValidationError('object_id cannot be empty')
        preauth_token['token_id'] = uuid.uuid4().hex
        preauth_token['action'] = action
        preauth_token['resource'] = resource
        result = self.preauth_api.create_preauth_token(preauth_token)

        headers = [('X-Preauth-Token', result['token_id'])]
        return wsgi.render_response(headers=headers)

    def list_preauth_tokens(self, context):
        user_id = context['environment']['KEYSTONE_AUTH_CONTEXT']['user_id']
        account_id = context['environment']['KEYSTONE_AUTH_CONTEXT']['account_id']
        user = self.identity_api.get_user(user_id)
        ## if user is root then
        if user.get('type') == 'root':
            tokens = self.preauth_api.list_preauth_token_in_account(account_id)

        tokens = self.preauth_api.list_preauth_token_of_user(user_id)
        return tokens

    def revoke_preauth_token(self, context):
        if 'X-Preauth-Token' not in context.get('headers'):
            raise exception.ValidationError('X-Preauth-Token not found in headers')
        token_id = context.get('headers')['X-Preauth-Token']
        user_id = context['environment']['KEYSTONE_AUTH_CONTEXT']['user_id']
        return self.preauth_api.revoke_preauth_token(token_id, user_id)

    def validate_preauth_token_post(self, context, **kwargs):
        is_authorized = True
        try:
            action_resource_list = kwargs['action_resource_list'][0]
            action = action_resource_list['action']
            resource = action_resource_list['resource']
            object_id = action_resource_list['object_id']
            token_id = context['headers']['X-Preauth-Token']
        except KeyError as e:
            raise exception.ValidationError(attribute=e,
                                        target='body')

        user_id, account_id = self.preauth_api.get_user_from_token_id(token_id)
        resource_acc_id = resource.split(':')[3].strip()
        if resource_acc_id == '':
            var = resource.split(':')
            var[3] = account_id
            resource = ':'.join(var)
        elif len(resource_acc_id) == 32:
            var = resource.split(':')
            var[3] = account_id[-12:]
            resource = ':'.join(var)
        elif len(resource_acc_id) != 12:
            raise exception.ValidationError('Invalid Account id')

        is_authorized = self.jio_policy_api.is_user_authorized(user_id, account_id, action,
                                                           resource, False)
        is_authorized = is_authorized and self.preauth_api.is_preauth_token_valid(action,
                                                                              resource,
                                                                              object_id,
                                                                              token_id)
        if not is_authorized:
            raise exception.Unauthorized('You are not authorized to perform this action');

