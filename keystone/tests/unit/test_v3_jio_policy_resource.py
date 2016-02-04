import uuid
import unittest
import json
import unittest
from keystone.tests.unit import test_v3
from keystone.common import dependency
import copy 

@dependency.requires('jio_policy_api')
class JioPolicyResourceTestCase(test_v3.RestfulTestCase):

    def setUp(self):
        super(JioPolicyResourceTestCase, self).setUp()
        self.jio_policy = self.new_resource_jio_policy_ref()
        self.jio_policy_id = self.jio_policy.get('id')
        self.jio_policy_api.create_resource_based_policy(self.project_id, self.jio_policy_id, copy.deepcopy(self.jio_policy))

    def test_create_jio_policy(self):
        ref = self.new_resource_jio_policy_ref()
        r = self.get(
                '/?Action=CreateResourceBasedPolicy&PolicyDocument=%(policy)s' % {
                'policy': json.dumps(ref)})
        return self.assertValidJioPolicyResponse(r, ref)
    
    def test_create_jio_policy_incorrect_resource_type_fail(self):
        ref = self.new_jio_policy_ref()
        statement = ref.get('statement')[0]
        resource = statement.get('resource')[0]
        resource_part = resource.split(':')
        resource_part[4] = uuid.uuid4().hex
        resource=':'.join(resource_part)
        statement['resource']= [resource]
        ref['statement']=[statement]
        r = self.get(
                '/?Action=CreatePolicy&PolicyDocument=%(policy)s' % {
                'policy':  json.dumps(ref)},
                expected_status = 400)

    @unittest.skip("roopali: Need to fix this)")
    def test_create_jio_policy_incorrect_service_type_fail(self):
        ref = self.new_jio_policy_ref()
        statement = ref.get('statement')[0]
        resource = statement.get('resource')[0]
        resource_part = resource.split(':')
        resource_part[2] = uuid.uuid4().hex
        resource=':'.join(resource_part)
        statement['resource']= [resource]
        ref['statement']=[statement]
        r = self.get(
                '/?Action=CreatePolicy&PolicyDocument=%(policy)s' % {
                'policy':  json.dumps(ref)},
                expected_status = 400)

    def test_list_jio_policies(self):
        r = self.get('?Action=ListPolicies')
        return self.assertValidJioPolicyListResponse(r, ref = self.jio_policy)

    def test_update_jio_policy(self):
        policy = self.new_jio_policy_ref()
        r = self.get(
                '/?Action=UpdatePolicy&Id=%(policy_id)s&PolicyDocument=%(policy)s' % {
                'policy_id': self.jio_policy_id, 'policy': json.dumps(policy)})
        policy['id'] = self.jio_policy_id
        self.assertValidJioPolicyResponse(r, policy)

    def test_delete_jio_policy(self):
        ref = self.new_jio_policy_ref()
        r = self.get(
                '?Action=DeletePolicy&Id=%(policy_id)s' % {
                    'policy_id':self.jio_policy_id}, expected_status = 204)

    def test_create_jio_policy_with_invalid_resource_fail(self):
        ref = self.new_jio_policy_ref()
        ref.get('statement')[0]['resource'] = uuid.uuid4().hex
        r = self.get(
                 '/?Action=CreatePolicy&PolicyDocument=%(policy)s' % {
                 'policy':  json.dumps(ref)}, 
                 expected_status = 400)

    def test_create_jio_policy_with_invalid_action_fail(self):
        ref = self.new_jio_policy_ref()
        ref.get('statement')[0]['action'] = uuid.uuid4().hex
        r = self.get(
                '/?Action=CreatePolicy&PolicyDocument=%(policy)s' % {
                'policy':  json.dumps(ref)}, 
                expected_status = 400)

    def test_list_jio_policy_with_invalid_token_fail(self):
        r = self.get('/?Action=CreatePolicy',
                     token = uuid.uuid4().hex,
                     expected_status = 401)

    def test_get_jio_policy_with_invalid_policy_id_fail(self):
        r = self.get(
                '/?Action=GetPolicy&Id=%(policy_id)s' % {
                'policy_id': uuid.uuid4().hex},
                expected_status = 404)

    def test_attach_policy_to_user(self):
        r = self.get(
                '/?Action=AttachPolicyToUser&UserId=%(user_id)s&PolicyId=%(policy_id)s' % {
                'policy_id': self.jio_policy_id, 'user_id': self.user_id}, expected_status = 204)

    def test_detach_policy_from_user(self):
        r = self.get(
                '/?Action=DetachPolicyFromUser&UserId=%(user_id)s&PolicyId=%(policy_id)s' % {
                'policy_id': self.jio_policy_id, 'user_id': self.user_id}, expected_status = 204)

    def test_attach_policy_to_group(self):
        new_group = {'domain_id': self.domain_id, 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        r = self.get(
                '/?Action=AttachPolicyToGroup&GroupId=%(group_id)s&PolicyId=%(policy_id)s' % {
                'policy_id': self.jio_policy_id, 'group_id':  new_group['id']}, expected_status = 204)

    def test_detach_policy_from_group(self):
        new_group = {'domain_id': self.domain_id, 'name': uuid.uuid4().hex}
        new_group = self.identity_api.create_group(new_group)
        r = self.get(
                '/?Action=DetachPolicyFromGroup&GroupId=%(group_id)s&PolicyId=%(policy_id)s' % {
                'policy_id': self.jio_policy_id, 'group_id':  new_group['id']}, expected_status = 204)

