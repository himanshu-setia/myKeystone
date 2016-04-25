from keystone.common import router
from keystone.common import wsgi
from keystone.preauth import controllers
from keystone.common import json_home

class Routers(wsgi.RoutersBase):
    def append_v3_routers(self, mapper, routers):
        preauth_token_controller = controllers.PreauthTokenV3()

        self._add_resource(
            mapper, preauth_token_controller,
            path = '/preauth-token',
            post_action = 'create_preauth_token',
            delete_action = 'revoke_preauth_token',
            rel=json_home.build_v3_resource_relation('preauth_token')
            )

        self._add_resource(
            mapper, preauth_token_controller,
            path = '/list-preauth-token',
            get_action = 'list_preauth_tokens',
            rel=json_home.build_v3_resource_relation('preauth_token')
            )
        self._add_resource(
            mapper, preauth_token_controller,
            path = '/preauth-token-auth',
            post_action = 'validate_preauth_token_post',
            rel=json_home.build_v3_resource_relation('preauth_token')
            )
