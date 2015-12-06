import uuid
import copy
import unittest

from keystone.tests.unit import test_v3
from keystone.common import dependency

@dependency.requires('jio_policy_api')
class JioPolicyTestCase(test_v3.RestfulTestCase):

    def setUp(self):
        super(JioPolicyTestCase, self).setUp()
        self.jio_policy = self.new_jio_policy_ref()
        self.jio_policy_id = self.jio_policy.get('id')
        self.jio_policy_api.create_policy(self.project_id, self.jio_policy_id, copy.deepcopy(self.jio_policy))

    def test_get_jio_policy(self):
        r = self.get(
                '/jio_policies/%(policy_id)s' % {
                    'policy_id': self.jio_policy_id})
        return self.assertValidJioPolicyResponse(r, self.jio_policy)

    def test_create_jio_policy(self):
        ref = self.new_jio_policy_ref()
        r = self.post(
                '/jio_policies',
                body={'policy': ref})
        return self.assertValidJioPolicyResponse(r, ref)

    def test_list_jio_policies(self):
        r = self.get('/jio_policies')
        return self.assertValidJioPolicyListResponse(r, ref = self.jio_policy)

    def test_update_jio_policy(self):
        policy = self.new_jio_policy_ref()
        r = self.patch(
                      '/jio_policies/%(policy_id)s' % {'policy_id': self.jio_policy_id},
                      body={'policy': policy})
        policy['id'] = self.jio_policy_id
        self.assertValidJioPolicyResponse(r, policy)

    def test_delete_jio_policy(self):
        ref = self.new_jio_policy_ref()
        r = self.delete(
                '/jio_policies/%(policy_id)s' % {
                    'policy_id':self.jio_policy_id})

    def test_create_jio_policy_with_invalid_resource_fail(self):
        ref = self.new_jio_policy_ref()
        ref.get('statement')[0]['resource'] = 'xyz'
        r = self.post(
                     '/jio_policies',
                     body={'policy': ref},
                     expected_status = 400)

    def test_create_jio_policy_with_invalid_action_fail(self):
        ref = self.new_jio_policy_ref()
        ref.get('statement')[0]['action'] = 'xyz'
        r = self.post(
                      '/jio_policies',
                      body={'policy': ref},
                      expected_status = 400)

    def test_list_jio_policy_with_invalid_token_fail(self):
        r = self.get('/jio_policies',
                     token = uuid.uuid4().hex,
                     expected_status = 401)

    def test_get_jio_policy_with_invalid_policy_id_fail(self):
        false_policy_id = uuid.uuid4().hex
        r = self.get(
                     '/jio_policies/%(policy_id)s' % {
                          'policy_id': false_policy_id},
                     expected_status = 404)

    def test_attach_policy_to_user(self):
        r = self.put(
                '/jio_policies/%(policy_id)s/users/%(user_id)s' %
                {'policy_id': self.jio_policy_id, 'user_id': self.user_id})

    def test_detach_policy_from_user(self):
        r = self.delete(
                       '/jio_policies/%(policy_id)s/users/%(user_id)s' % {
                           'policy_id': self.jio_policy_id, 'user_id': self.user_id})

    def test_attach_policy_to_group(self):
        new_group = {'domain_id': self.domain_id, 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        r = self.put(
                    '/jio_policies/%(policy_id)s/groups/%(group_id)s' % 
                    {'policy_id': self.jio_policy_id, 'group_id':  new_group['id']})
        
    def test_detach_policy_from_group(self):
        new_group = {'domain_id': self.domain_id, 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        r = self.delete(
                        '/jio_policies/%(policy_id)s/groups/%(group_id)s' % {
                            'policy_id': self.jio_policy_id, 'group_id':  new_group['id']})
