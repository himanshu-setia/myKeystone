import uuid
import copy

from keystone.tests.unit import test_v3
from keystone.common import dependency

@dependency.requires('jio_policy_api')
class TestAuthWithActionResource(test_v3.RestfulTestCase):
    def setUp(self):
        super(TestAuthWithActionResource, self).setUp()
        self.jio_policy = self.new_jio_policy_ref()
        self.jio_policy_api.create_policy(self.project_id, self.jio_policy.get('id'), copy.deepcopy(self.jio_policy))
        self.jio_policy_api.attach_policy_to_user(self.jio_policy.get('id'), self.user_id)

    def test_auth_with_action_resource(self):
        scoped_token = self.get_scoped_token()
        headers = {'X-Subject-Token': scoped_token}
        r = self.get('/authorize?action=%(action_id)s&resource=%(resource_id)s' % {
            'action_id': self.jio_policy.get('statement')[0].get('action')[0],
            'resource_id' : self.jio_policy.get('statement')[0].get('resource')[0]},
            headers=headers)
    
    def test_auth_with_no_action_resource_fail(self):
        r = self.get('/authorize',
                expected_status = 400)

    def test_auth_with_false_action_fail(self):
        r = self.get('/authorize?action=%(action_id)s&resource=%(resource_id)s' % {
            'action_id': uuid.uuid4().hex, 'resource_id' : self.jio_policy.get('statement')[0].get('resource')[0]},
            expected_status = 400)

    def test_auth_with_false_resource_fail(self):
        r = self.get('/authorize?action=%(action_id)s&resource=%(resource_id)s' % {
            'action_id' : self.jio_policy.get('statement')[0].get('action')[0], 'resource_id' : uuid.uuid4().hex},
            expected_status = 400)

    def test_jio_policy_with_wildcards_attach_user_ref(self):
        self.jio_policy_with_wildcards = self.new_jio_policy_with_wildcards_ref()
        self.jio_policy_api.create_policy(self.project_id, self.jio_policy_with_wildcards.get('id'), copy.deepcopy(self.jio_policy_with_wildcards))
        self.jio_policy_api.attach_policy_to_user(self.jio_policy_with_wildcards.get('id'), self.user_id)
        scoped_token = self.get_scoped_token()
        headers = {'X-Subject-Token': scoped_token}
        r = self.get('/authorize?action=%(action_id)s&resource=%(resource_id)s' % {
            'action_id': self.jio_policy_with_wildcards.get('statement')[0].get('action')[0],
            'resource_id' : self.jio_policy_with_wildcards.get('statement')[0].get('resource')[0]},
            headers=headers, expected_status = 403)
