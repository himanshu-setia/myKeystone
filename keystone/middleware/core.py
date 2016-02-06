# Copyright 2012 OpenStack Foundation
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

import hashlib


from oslo_config import cfg
from oslo_log import log
from oslo_middleware import sizelimit
from oslo_serialization import jsonutils
import six
import requests
from keystone.common import authorization
from keystone.common import wsgi
from keystone import exception
from keystone.i18n import _LW
from keystone.models import token_model
from keystone.openstack.common import versionutils



CONF = cfg.CONF
LOG = log.getLogger(__name__)
ec2_opts = [
    cfg.StrOpt('keystone_url',
               default='http://127.0.0.1:5000/v2.0',
               help='URL to get token from ec2 request.'),
    cfg.StrOpt('keystone_ec2_tokens_url',
               default='$keystone_url/ec2tokens',
               help='URL to get token from ec2 request.'),
    cfg.IntOpt('ec2_timestamp_expiry',
               default=300,
               help='Time in seconds before ec2 timestamp expires'),
]


CONF = cfg.CONF
CONF.register_opts(ec2_opts)


EMPTY_SHA256_HASH = (
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
# This is the buffer size used when calculating sha256 checksums.
# Experimenting with various buffer sizes showed that this value generally
# gave the best result (in terms of performance).
PAYLOAD_BUFFER = 1024 * 1024





# Header used to transmit the auth token
AUTH_TOKEN_HEADER = 'X-Auth-Token'


# Header used to transmit the subject token
SUBJECT_TOKEN_HEADER = 'X-Subject-Token'


# Environment variable used to pass the request context
CONTEXT_ENV = wsgi.CONTEXT_ENV


# Environment variable used to pass the request params
PARAMS_ENV = wsgi.PARAMS_ENV


class TokenAuthMiddleware(wsgi.Middleware):
    def process_request(self, request):
        token = request.headers.get(AUTH_TOKEN_HEADER)
        context = request.environ.get(CONTEXT_ENV, {})
        context['token_id'] = token
        if SUBJECT_TOKEN_HEADER in request.headers:
            context['subject_token_id'] = (
                request.headers.get(SUBJECT_TOKEN_HEADER))
        else:
            context['subject_token_id'] = (
                request.headers.get(AUTH_TOKEN_HEADER))
        request.environ[CONTEXT_ENV] = context


class AdminTokenAuthMiddleware(wsgi.Middleware):
    """A trivial filter that checks for a pre-defined admin token.

    Sets 'is_admin' to true in the context, expected to be checked by
    methods that are admin-only.

    """

    def process_request(self, request):
        token = request.headers.get(AUTH_TOKEN_HEADER)
        context = request.environ.get(CONTEXT_ENV, {})
        context['is_admin'] = (token == CONF.admin_token)
        request.environ[CONTEXT_ENV] = context


class PostParamsMiddleware(wsgi.Middleware):
    """Middleware to allow method arguments to be passed as POST parameters.

    Filters out the parameters `self`, `context` and anything beginning with
    an underscore.

    """

    def process_request(self, request):
        params_parsed = request.params
        params = {}
        for k, v in six.iteritems(params_parsed):
            if k in ('self', 'context'):
                continue
            if k.startswith('_'):
                continue
            params[k] = v
        if 'auth' in params and 'password' in params['auth']['identity']['methods']:
            account_id = params["auth"]["identity"]["password"]["user"]["account"]["id"]
            params["auth"]["scope"] = {"account":{"id":account_id}}
        request.environ[PARAMS_ENV] = params


class JsonBodyMiddleware(wsgi.Middleware):
    """Middleware to allow method arguments to be passed as serialized JSON.

    Accepting arguments as JSON is useful for accepting data that may be more
    complex than simple primitives.

    Filters out the parameters `self`, `context` and anything beginning with
    an underscore.

    """
    def process_request(self, request):
        # Abort early if we don't have any work to do
        params_json = request.body
        if not params_json:
            return

        # Reject unrecognized content types. Empty string indicates
        # the client did not explicitly set the header
        if request.content_type not in ('application/json', ''):
            e = exception.ValidationError(attribute='application/json',
                                          target='Content-Type header')
            return wsgi.render_exception(e, request=request)

        params_parsed = {}
        try:
            params_parsed = jsonutils.loads(params_json)
        except ValueError:
            e = exception.ValidationError(attribute='valid JSON',
                                          target='request body')
            return wsgi.render_exception(e, request=request)
        finally:
            if not params_parsed:
                params_parsed = {}

        if not isinstance(params_parsed, dict):
            e = exception.ValidationError(attribute='valid JSON object',
                                          target='request body')
            return wsgi.render_exception(e, request=request)

        params = {}
        for k, v in six.iteritems(params_parsed):
            if k in ('self', 'context'):
                continue
            if k.startswith('_'):
                continue
            params[k] = v
        if 'auth' in params and 'password' in params['auth']['identity']['methods']:
            account_id = params["auth"]["identity"]["password"]["user"]["account"]["id"]
            params["auth"]["scope"] = {"account":{"id":account_id}}
        request.environ[PARAMS_ENV] = params


class XmlBodyMiddleware(wsgi.Middleware):
    """De/serialize XML to/from JSON."""

    def print_warning(self):
        LOG.warning(_LW('XML support has been removed as of the Kilo release '
                        'and should not be referenced or used in deployment. '
                        'Please remove references to XmlBodyMiddleware from '
                        'your configuration. This compatibility stub will be '
                        'removed in the L release'))

    def __init__(self, *args, **kwargs):
        super(XmlBodyMiddleware, self).__init__(*args, **kwargs)
        self.print_warning()


class XmlBodyMiddlewareV2(XmlBodyMiddleware):
    """De/serialize XML to/from JSON for v2.0 API."""


class XmlBodyMiddlewareV3(XmlBodyMiddleware):
    """De/serialize XML to/from JSON for v3 API."""


class NormalizingFilter(wsgi.Middleware):
    """Middleware filter to handle URL normalization."""

    def process_request(self, request):
        """Normalizes URLs."""
        # Removes a trailing slash from the given path, if any.
        if (len(request.environ['PATH_INFO']) > 1 and
                request.environ['PATH_INFO'][-1] == '/'):
            request.environ['PATH_INFO'] = request.environ['PATH_INFO'][:-1]
        # Rewrites path to root if no path is given.
        elif not request.environ['PATH_INFO']:
            request.environ['PATH_INFO'] = '/'


class RequestBodySizeLimiter(sizelimit.RequestBodySizeLimiter):
    @versionutils.deprecated(
        versionutils.deprecated.KILO,
        in_favor_of='oslo_middleware.sizelimit.RequestBodySizeLimiter',
        remove_in=+1,
        what='keystone.middleware.RequestBodySizeLimiter')
    def __init__(self, *args, **kwargs):
        super(RequestBodySizeLimiter, self).__init__(*args, **kwargs)


class AuthContextMiddleware(wsgi.Middleware):
    """Build the authentication context from the request auth token."""

    def _build_auth_context(self, request):
        token_id = request.headers.get(AUTH_TOKEN_HEADER).strip()
        if token_id == CONF.admin_token:
            # NOTE(gyee): no need to proceed any further as the special admin
            # token is being handled by AdminTokenAuthMiddleware. This code
            # will not be impacted even if AdminTokenAuthMiddleware is removed
            # from the pipeline as "is_admin" is default to "False". This code
            # is independent of AdminTokenAuthMiddleware.
            return {}

        context = {'token_id': token_id}
        context['environment'] = request.environ

        try:
            token_ref = token_model.KeystoneToken(
                token_id=token_id,
                token_data=self.token_provider_api.validate_token(token_id))
            # TODO(gyee): validate_token_bind should really be its own
            # middleware
            wsgi.validate_token_bind(context, token_ref)
            return authorization.token_to_auth_context(token_ref)
        except exception.TokenNotFound:
            LOG.warning(_LW('RBAC: Invalid token'))
            raise exception.Unauthorized()



    """Authenticate an EC2 request with keystone and convert to context."""

    def _get_signature(self, req):
        """Extract the signature from the request.
        This can be a get/post variable or for version 4 also in a header
        called 'Authorization'.
        - params['Signature'] == version 0,1,2,3
        - params['X-Amz-Signature'] == version 4
        - header 'Authorization' == version 4
        """
        sig = req.params.get('Signature') or req.params.get('X-Amz-Signature')
        if sig is not None:
            return sig

        if 'Authorization' not in req.headers:
            return None

        auth_str = req.headers['Authorization']
        if not auth_str.startswith('AWS4-HMAC-SHA256'):
            return None

        return auth_str.partition("Signature=")[2].split(',')[0]

    def _get_access(self, req):
        """Extract the access key identifier.
        For version 0/1/2/3 this is passed as the AccessKeyId parameter, for
        version 4 it is either an X-Amz-Credential parameter or a Credential=
        field in the 'Authorization' header string.
        """
        access = req.params.get('AWSAccessKeyId')
        if access is not None:
            return access

        cred_param = req.params.get('X-Amz-Credential')
        if cred_param:
            access = cred_param.split("/")[0]
            if access is not None:
                return access

        if 'Authorization' not in req.headers:
            return None
        auth_str = req.headers['Authorization']
        if not auth_str.startswith('AWS4-HMAC-SHA256'):
            return None
        cred_str = auth_str.partition("Credential=")[2].split(',')[0]
        return cred_str.split("/")[0]


    def _verify_signature(self, req):
       body_hash = hashlib.sha256(req.body).hexdigest()
       
       signature = self._get_signature(req)
       LOG.warning(_LW( signature))
       if not signature:
           msg = ("Signature not provided")
           return None, None
       access = self._get_access(req)
       if not access:
           msg = _("Access key not provided")
           return None, None

       if 'X-Amz-Signature' in req.params or 'Authorization' in req.headers:
           params = {}
       else:
           # Make a copy of args for authentication and signature verification
           params = dict(req.params)
           # Not part of authentication args
           params.pop('Signature', None)
           params.pop('signature', None)

       host = req.headers.get('X-Forwarded-Host',req.host)
       cred_dict = {
           'access': access,
           'signature': signature,
           'host': host,
           'verb': req.method,
           'path': req.path,
           'params': params,
           'headers': req.headers,
           'body_hash': body_hash
       }
       LOG.warning(cred_dict)

       token_url = CONF.keystone_ec2_tokens_url
       if "ec2" in token_url:
           creds = {'ec2Credentials': cred_dict}
       else:
           creds = {'auth': {'OS-KSEC2:ec2Credentials': cred_dict}}
       creds_json = jsonutils.dumps(creds)
       headers = {'Content-Type': 'application/json'}

       verify = False #CONF.ssl_ca_file or not CONF.ssl_insecure
       LOG.warning("making the ec2 request2")
       LOG.warning(creds_json)
       response = requests.request('POST', token_url, verify=verify,
                                   data=creds_json, headers=headers)
       status_code = response.status_code
       if status_code != 200:
           msg = response.reason
           raise exception.Unauthorized()

       result = response.json() 
       LOG.debug(result)
       token_id = None
       account_id = None
       if 'token' in result:
           token_id = response.headers['x-subject-token']
       else: 
           token_id = result['access']['token']['id']
           account_id = result['access']['token']['tenant']['account_id']
       req.headers[AUTH_TOKEN_HEADER] = token_id
       return token_id, account_id

    def process_request(self, request):
        account_id = None
        if AUTH_TOKEN_HEADER not in request.headers:
            LOG.debug(('Auth token not in the request header. '
                       'Will not build auth context.'))
            LOG.warning(request.path)
            if 'ec2' in request.path:
                return
            else:
                LOG.warning("calling verify signature")
                token_id, account_id = self._verify_signature(request)
                if not token_id:
                    return;
#            return
        if authorization.AUTH_CONTEXT_ENV in request.environ:
            msg = _LW('Auth context already exists in the request environment')
            LOG.warning(msg)
            return
        auth_context = self._build_auth_context(request)
        if account_id is not None:
            auth_context["project_id"] = account_id
            auth_context["account_id"] = account_id
        LOG.debug('RBAC: auth_context: %s', auth_context)
        request.environ[authorization.AUTH_CONTEXT_ENV] = auth_context

