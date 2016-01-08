from oslo_config import cfg
from oslo_log import log

from keystone.common import controller
from keystone.common import dependency
from keystone import exception
from keystone.i18n import _, _LW
from keystone import notifications
from keystone import identity
from keystone import jio_policy
CONF = cfg.CONF
LOG = log.getLogger(__name__)


@dependency.requires('assignment_api', 'identity_api', 'resource_api','jio_policy_api')
class RootV3(controller.V3Controller):

    @controller.v2_deprecated
    def genericmapper(self, context):
        self.assert_admin(context)
        
	query_strings = context.get('query_string', None)
	Action = query_strings['Action']
        user_controller = identity.controllers.UserV3()
	if Action == 'CreateUser':
	    user = {}
	    user["project_id"] = query_strings['Project_id']
	    user["domain_id"] = query_strings['Domain_id']
	    user["email"] = query_strings['Email']
	    user["enabled"] = True
            user["name"] = query_strings['Name']
	    user["pasword"] = query_strings['Password']
            return user_controller.create_user(context,user)
        elif Action == 'GetUser':
            return user_controller.get_user(context,query_strings['User_id'])
        


        jio_policy_controller = jio_policy.controllers.JioPolicyV3()
        if Action == 'ListActions':
            return jio_policy_controller.list_actions(context)
        elif Action == 'CreatePolicy':
            policy_document = query_strings['PolicyDocument']
            return jio_policy_controller.create_policy(context, policy_document)
        elif Action == 'ListPolicies':
            return jio_policy_controller.list_policies(context)
        elif Action == 'GetPolicy':
            jio_policy_id = query_strings['PolicyId']
            return jio_policy_controller.get_policy(context, jio_policy_id)
        elif Action == 'DeletePolicy':
            jio_policy_id = query_strings['PolicyId']
            return jio_policy_controller.delete_policy(context, jio_policy_id)
        elif Action == 'UpdatePolicy':
            policy_document = query_strings['PolicyDocument']
            jio_policy_id = query_strings['PolicyId']
            return jio_policy_controller.update_policy(context, jio_policy_id, policy_document)
        elif Action == 'AttachPolicyToUser':
            jio_policy_id = query_strings['PolicyId']
            user_id = query_strings['UserId']
            return jio_policy_controller.attach_policy_to_user(context, jio_policy_id, user_id)
        elif Action == 'DetachPolicyFromUser':
            jio_policy_id = query_strings['PolicyId']
            user_id = query_strings['UserId']
            jio_policy_controller.detach_policy_from_user(context, jio_policy_id, user_id)
        elif Action == 'AttachPolicyToGroup':
            jio_policy_id = query_strings['PolicyId']
            group_id = query_strings['GroupId']
            return jio_policy_controller.attach_policy_to_group(context, jio_policy_id, group_id)
        elif Action == 'DetachPolicyFromGroup':
            jio_policy_id = query_strings['PolicyId']
            group_id = query_strings['GroupId']
            jio_policy_controller.detach_policy_from_group(context, jio_policy_id,group_id)
