#Copyright 2012 OpenStack Foundation
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

from oslo_config import cfg
from oslo_log import log

from keystone.common import controller
from keystone.common import dependency
from keystone import exception
from keystone.i18n import _, _LW
from keystone import notifications
from keystone import identity
from keystone import jio_policy
from keystone import credential as cred

import json
CONF = cfg.CONF
LOG = log.getLogger(__name__)

class RootV3(controller.V3Controller):

    def genericmapper(self, context):

        query_string = context.get('query_string', None)
        Action = query_string['Action']
        user_controller = identity.controllers.UserV3()
        group_controller = identity.controllers.GroupV3()
        credential_controller = cred.controllers.CredentialV3()
        jio_policy_controller = jio_policy.controllers.JioPolicyV3()
        if Action == 'CreateUser':
            user = {}
            if 'Email' in query_string:
                user['email'] = query_string['Email']
            if 'Enabled' in query_string:
                user['enabled'] = (False, True) [query_string['Enabled'] == 'Yes']
            else:
                user['enabled'] = True
            if 'Name' in query_string:
                user['name'] = query_string['Name']
            if 'Password' in query_string:
                user['password'] = query_string['Password']

            return user_controller.create_user(context,user)
        elif Action == 'GetUser':
            return user_controller.get_user(context,query_string['Id'])
        elif Action == 'ListUsers':
            return user_controller.list_users(context)
        elif Action == 'UpdateUser':
            user = {}
            if 'Email' in query_string:
                user['email'] = query_string['Email']
            if 'Enabled' in query_string:
            	user['enabled'] = (False, True) [query_string['Enabled'] == 'Yes']
            if 'Name' in query_string:
                user['name'] = query_string['Name']
            if 'Password' in query_string:
                user['password'] = query_string['Password']

            return user_controller.update_user(context,query_string['Id'],user)

        elif Action == 'DeleteUser':
            return user_controller.delete_user(context,query_string['Id'])

        elif Action == 'ListGroupsForUser':
            return group_controller.list_groups_for_user(context,query_string['Id'])

        elif Action == 'CreateGroup':
            group = {}
            if 'Description' in query_string:
                group['description'] = query_string['Description']
            if 'Name' in query_string:
                group['name'] = query_string['Name']

            return group_controller.create_group(context,group)

        elif Action == 'GetGroup':
            return group_controller.get_group(context,query_string['Id'])

        elif Action == 'ListGroups':
            return group_controller.list_groups(context)
          
        elif Action == 'UpdateGroup':
            group = {}
            if 'Description' in query_string:
                group['description'] = query_string['Description']
            if 'Name' in query_string:
                group['name'] = query_string['Name']

            return group_controller.update_group(context,query_string['Id'],group)

        elif Action == 'DeleteGroup':
            return group_controller.delete_group(context,query_string['Id'])

        elif Action == 'ListUserInGroup':
            return user_controller.list_users_in_group(context,query_string['Id'])

        elif Action == 'AssignUserToGroup':
            return user_controller.add_user_to_group(context,query_string['UserId'],query_string['GroupId'])

        elif Action == 'RemoveUserFromGroup':
            return user_controller.remove_user_from_group(context,query_string['UserId'],query_string['GroupId'])

        elif Action == 'CheckUserInGroup':
            return user_controller.check_user_in_group(context,query_string['UserId'],query_string['GroupId'])

        elif Action == 'CreateCredential':
            credential = {}
            if 'Type' in query_string:
                credential['type'] = query_string['Type']
            if 'UserId' in query_string:
                credential['user_id'] = query_string['UserId']
            return credential_controller.create_credential(context,credential)

        elif Action == 'ListCredentials':
            return credential_controller.list_credentials(context)

        elif Action == 'GetCredential':
            return credential_controller.get_credential(context,query_string['Id'])

        elif Action == 'DeleteCredential':
            return credential_controller.delete_credential(context,query_string['Id'])
        if Action == 'ListActions':
            return jio_policy_controller.list_actions(context)
        elif Action == 'CreatePolicy':
            policy_document = json.loads(query_string['PolicyDocument'])
            return jio_policy_controller.create_policy(context, policy_document)
        elif Action == 'ListPolicies':
            return jio_policy_controller.list_policies(context)
        elif Action == 'GetPolicy':
            jio_policy_id = query_string['Id']
            return jio_policy_controller.get_policy(context, jio_policy_id)
        elif Action == 'DeletePolicy':
            jio_policy_id = query_string['Id']
            return jio_policy_controller.delete_policy(context, jio_policy_id)
        elif Action == 'UpdatePolicy':
            policy_document = json.loads(query_string['PolicyDocument'])
            jio_policy_id = query_string['Id']
            return jio_policy_controller.update_policy(context, jio_policy_id, policy_document)
        elif Action == 'AttachPolicyToUser':
            jio_policy_id = query_string['PolicyId']
            user_id = query_string['UserId']
            return jio_policy_controller.attach_policy_to_user(context, jio_policy_id, user_id)
        elif Action == 'DetachPolicyFromUser':
            jio_policy_id = query_string['PolicyId']
            user_id = query_string['UserId']
            return jio_policy_controller.detach_policy_from_user(context, jio_policy_id, user_id)
        elif Action == 'AttachPolicyToGroup':
            jio_policy_id = query_string['PolicyId']
            group_id = query_string['GroupId']
            return jio_policy_controller.attach_policy_to_group(context, jio_policy_id, group_id)
        elif Action == 'DetachPolicyFromGroup':
            jio_policy_id = query_string['PolicyId']
            group_id = query_string['GroupId']
            jio_policy_controller.detach_policy_from_group(context, jio_policy_id,group_id)

        elif Action == 'CreateResourceBasedPolicy':
            #import pdb;pdb.set_trace()
            policy_document = json.loads(query_string['PolicyDocument'])
            return jio_policy_controller.create_resource_based_policy(context, policy_document)
        elif Action == 'UpdateResourceBasedPolicy':
            policy_document = json.loads(query_string['PolicyDocument'])
            jio_policy_id = query_string['Id']
            return jio_policy_controller.update_resource_based_policy(context, jio_policy_id, policy_document)
        elif Action == 'DeleteResourceBasedPolicy':
            jio_policy_id = query_string['Id']
            return jio_policy_controller.delete_resource_based_policy(context, jio_policy_id)
        elif Action == 'AttachPolicyToResource':
            jio_policy_id = query_string['PolicyId']
            resource = json.loads(query_string['Resource'])
            return jio_policy_controller.attach_policy_to_resource(context, jio_policy_id, resource['resource'])
        elif Action == 'DetachPolicyFromResource':
            jio_policy_id = query_string['PolicyId']
            resource = json.loads(query_string['Resource'])
            jio_policy_controller.detach_policy_from_resource(context, jio_policy_id, resource['resource'])        

        else:
            raise exception.ActionNotFound(action = Action)
