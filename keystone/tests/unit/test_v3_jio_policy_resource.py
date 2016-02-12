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
        self.jio_res_type = self.jio_policy.get('res_type')
        self.jio_policy_api.create_resource_based_policy(self.project_id, self.jio_policy_id, copy.deepcopy(self.jio_policy))


    def test_get_jio_policy(self):
        r = self.get(
                '/?Action=GetResourceBasedPolicy&Id=%(policy_id)s' % {
                    'policy_id': self.jio_policy_id})
        return self.assertValidJioPolicyResponse(r, self.jio_policy)

    def test_get_jio_policy_summary(self):
        r = self.get(
                '/?Action=GetResourceBasedPolicySummary&Id=%(policy_id)s' % {
                    'policy_id': self.jio_policy_id})
        return self.assertValidJioPolicySummaryResponse(r, self.jio_policy)

    def test_create_jio_policy(self):
        ref = self.new_resource_jio_policy_ref()
        r = self.get(
                '/?Action=CreateResourceBasedPolicy&PolicyDocument=%(policy)s' % {
                'policy': json.dumps(ref)})
        return self.assertValidJioPolicyResponse(r, ref)
    
    def test_create_jio_policy_incorrect_principle_type_fail(self):
        ref = self.new_resource_jio_policy_ref()
        statement = ref.get('statement')[0]
        principle = statement.get('principle')[0]
        principle_part = principle.split(':')
        principle_part[1] = uuid.uuid4().hex
        principle=':'.join(principle_part)
        statement['principle']= [principle]
        ref['statement']=[statement]
        r = self.get(
                '/?Action=CreateResourceBasedPolicy&PolicyDocument=%(policy)s' % {
                'policy':  json.dumps(ref)},
                expected_status = 400)

    def test_create_jio_policy_same_principle_account_fail(self):
        ref = self.new_resource_jio_policy_ref()
        statement = ref.get('statement')[0]
        principle = statement.get('principle')[0]
        principle_part = principle.split(':')
        principle_part[0] = self.project_id
        principle=':'.join(principle_part)
        statement['principle']= [principle]
        ref['statement']=[statement]
        r = self.get(
                '/?Action=CreateResourceBasedPolicy&PolicyDocument=%(policy)s' % {
                'policy':  json.dumps(ref)},
                expected_status = 400)

    def test_create_jio_policy_incorrect_principle_id_fail(self):
        ref = self.new_resource_jio_policy_ref()
        statement = ref.get('statement')[0]
        principle = statement.get('principle')[0]
        principle_part = principle.split(':')
        principle_part[2] = uuid.uuid4().hex
        principle=':'.join(principle_part)
        statement['principle']= [principle]
        ref['statement']=[statement]
        r = self.get(
                '/?Action=CreateResourceBasedPolicy&PolicyDocument=%(policy)s' % {
                'policy':  json.dumps(ref)},
                expected_status = 404)

    def test_update_jio_policy(self):
        policy = self.new_resource_jio_policy_ref()
        r = self.get(
                '/?Action=UpdateResourceBasedPolicy&Id=%(policy_id)s&PolicyDocument=%(policy)s' % {
                'policy_id': self.jio_policy_id, 'policy': json.dumps(policy)})
        policy['id'] = self.jio_policy_id
        self.assertValidJioPolicyResponse(r, policy)

    def test_delete_jio_policy(self):
        ref = self.new_resource_jio_policy_ref()
        r = self.get(
                '?Action=DeleteResourceBasedPolicy&Id=%(policy_id)s' % {
                    'policy_id':self.jio_policy_id}, expected_status = 204)

    def test_create_jio_policy_with_invalid_action_fail(self):
        ref = self.new_resource_jio_policy_ref()
        ref.get('statement')[0]['action'] = uuid.uuid4().hex
        r = self.get(
                '/?Action=CreateResourceBasedPolicy&PolicyDocument=%(policy)s' % {
                'policy':  json.dumps(ref)}, 
                expected_status = 400)

    def test_get_jio_policy_with_invalid_policy_id_fail(self):
        r = self.get(
                '/?Action=GetResourceBasedPolicy&Id=%(policy_id)s' % {
                'policy_id': uuid.uuid4().hex},
                expected_status = 404)

    def test_list_jio_policies(self):
        r = self.get('?Action=ListResourceBasedPolicies')
        return self.assertValidJioPolicyListResponse(r, ref = self.jio_policy)

    def test_attach_policy_to_resource(self):
        resource = self.new_resource(self.jio_res_type)
        r = self.get(
                '/?Action=AttachPolicyToResource&Resource=%(resource)s&PolicyId=%(policy_id)s' % {
                'policy_id': self.jio_policy_id, 'resource': json.dumps(resource)}, expected_status = 204)

    def test_detach_policy_from_resource(self):
        resource = self.new_resource(self.jio_res_type)
        r = self.get(
                '/?Action=AttachPolicyToResource&Resource=%(resource)s&PolicyId=%(policy_id)s' % {
                'policy_id': self.jio_policy_id, 'resource': json.dumps(resource)}, expected_status = 204)

        r = self.get(
                '/?Action=DetachPolicyFromResource&Resource=%(resource)s&PolicyId=%(policy_id)s' % {
                'policy_id': self.jio_policy_id, 'resource': json.dumps(resource)}, expected_status = 204)
