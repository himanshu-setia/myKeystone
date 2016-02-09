import uuid                                                                                                                                
import unittest
import json
from keystone.tests.unit import test_v3
from keystone.common import dependency
 
@dependency.requires('jio_policy_api', 'resource_api', 'identity_api')
class ServiceAccountTestCase(test_v3.RestfulTestCase):

    def setUp(self):
        super(ServiceAccountTestCase, self).setUp()
        self.new_account_id = uuid.uuid4().hex
        self.new_account = self.new_account_ref()
        self.new_account['id'] = self.new_account_id
        self.resource_api.create_account(self.new_account_id, self.new_account)

        self.new_user = self.new_user_ref(account_id=self.new_account_id)
        password = self.new_user['password']
        self.new_user = self.identity_api.create_user(self.new_user)
        self.new_user['password'] = password

        self.new_action_id =  uuid.uuid4().hex
        self.new_action_name = 'jrn:jcs:' + self.service.get('type') + ':*'
        service_type = self.service.get('type')
        self.jio_policy_api.create_action(self.new_action_id, self.new_action_name, service_type)

    def test_service_account_updation(self):
        isa_token = self.get_isa_scoped_token()
        services = {'services':[self.service.get('type')]}
        user_ids = {'userIds':[self.new_user.get('id')]}
        r = self.get('/?Action=UpdateServiceAccount&AccountId=%(account_id)s&Services=%(service)s&UserIds=%(user_id)s' % {'account_id': self.new_account_id, 'service':json.dumps(services), 'user_id':json.dumps(user_ids)}, token = isa_token)

    def test_service_account_updation_non_iam_special_account_fail(self):
        services = {'services':[self.service.get('type')]}
        user_ids = {'userIds':[self.new_user.get('id')]}
        r = self.get('/?Action=UpdateServiceAccount&AccountId=%(account_id)s&Services=%(service)s&UserIds=%(user_id)s' % {'account_id': self.new_account_id, 'service':json.dumps(services), 'user_id':json.dumps(user_ids)}, expected_status=403)
