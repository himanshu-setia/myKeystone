import uuid
import copy

from keystone.tests.unit import test_v3
from keystone.common import dependency

@dependency.requires('jio_policy_api')
class TestAuthWithActionResource(test_v3.RestfulTestCase):
    def setUp(self):
        super(TestAuthWithActionResource, self).setUp()
        self.action = self.new_action_ref()
        self.jio_policy = self.new_jio_policy_ref()
        self.jio_policy_api.create_policy(self.jio_policy.get('service'), self.project_id, self.jio_policy.get('id'), copy.deepcopy(self.jio_policy))

    def test_auth_with_action_resource(self):
        scoped_token = self.get_scoped_token()
        headers = {'X-Subject-Token': scoped_token}
        r = self.get('/authorize?action=%(action_id)s&resource=%(resource_id)s' % {
            'action_id': self.action.get('id'), 'resource_id' : self.jio_policy.get('statement')[0].get('resource')},
            headers=headers)
    
    def test_auth_with_no_action_resource_fail(self):
        r = self.get('/authorize',
                expected_status = 400)

    def test_auth_with_false_action_fail(self):
        r = self.get('/authorize?action=%(action_id)s&resource=%(resource_id)s' % {
                        'action_id': uuid.uuid4().hex, 'resource_id' : self.jio_policy.get('statement')[0].get('resource')},
                        expected_status = 404)

    def test_auth_with_false_resource_fail(self):
                r = self.get('/authorize?action=%(action_id)s&resource=%(resource_id)s' % {
                        'action_id' : self.action.get('id'), 'resource_id' : uuid.uuid4().hex},
                        expected_status = 404)
