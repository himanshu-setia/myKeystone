from oslo_config import cfg
from oslo_log import log

from keystone.common import controller
from keystone.common import dependency
from keystone import exception
from keystone.i18n import _, _LW
from keystone import notifications
from keystone import identity

CONF = cfg.CONF
LOG = log.getLogger(__name__)


@dependency.requires('assignment_api', 'identity_api', 'resource_api')
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
