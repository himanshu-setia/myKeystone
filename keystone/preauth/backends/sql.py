import uuid
import itertools
import copy
from datetime import datetime
from keystone.common import dependency
from keystone.common import sql
from keystone import exception
from keystone import preauth
from oslo_serialization import jsonutils
from oslo_utils import timeutils

class PreauthTokenModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'preauth_token'
    attribute = ['id', 'user_id', 'account_id', 'action', 'resource', 'object_id', 'expires']
    id =  sql.Column(sql.String(64), primary_key=True)
    user_id = sql.Column(sql.String(64), nullable=False)
    account_id = sql.Column(sql.String(length=64), nullable=False)
    action = sql.Column(sql.String(length=255), nullable=False)
    resource = sql.Column(sql.String(length=255), nullable=False)
    object_id = sql.Column(sql.String(length=255), nullable=True)
    expires = sql.Column(sql.DateTime, nullable=True)


class PreauthToken(preauth.Driver):

    @sql.handle_conflicts(conflict_message='Preauth token id already exist')
    def create_preauth_token(self, preauth_token):
        with sql.transaction() as session:
            session.add(PreauthTokenModel(
                     id = preauth_token['token_id'],
                     user_id = preauth_token.get('user_id', None),
                     account_id = preauth_token.get('account_id', None),
                     action = preauth_token.get('action', None),
                     resource = preauth_token.get('resource', None),
                     object_id = preauth_token.get('object_id', None),
                     expires = preauth_token.get('expires', None)))

    def _get_preauth_token(self, session, token_id):
        """Private method to get a PreauthTokenModel object"""
        ref = session.query(PreauthTokenModel).get(token_id)
        if not ref:
            raise exception.PreauthTokenNotFound(token_id=token_id)
        return ref

    def get_preauth_token(self, token_id):
        session= sql.get_session()
        return self._get_preauth_token(session, token_id)

    def list_preauth_token_in_account(self, account_id):
        session = sql.get_session()
        return session.query(PreauthTokenModel).filter_by(account_id=account_id)

    def list_preauth_token_of_user(self, user_id):
        session = sql.get_session()
        return session.query(PreauthTokenModel).filter_by(user_id=user_id)

    def revoke_preauth_token(self, token_id):
        session = sql.get_session()
        with session.begin():
            pre_auth_token = self._get_preauth_token(session, token_id)
            session.delete(pre_auth_token)

    def delete_user_preauth_token(self, user_id):
        session = sql.get_session()
        with session.begin():
            session.query(PreauthTokenModel).filter_by(user_id=user_id).delete()

    def get_user_from_token_id(self, token_id):
        session = sql.get_session()
        ref = session.query(PreauthTokenModel).get(token_id)
        current_time = timeutils.normalize_time(timeutils.utcnow())
        if not ref or (ref.expires is not None and ref.expires < current_time):
            raise exception.NotFound('url not found')

        return ref.user_id, ref.account_id

    def is_preauth_token_valid(self, action, resource, object_id, token_id):
        session = sql.get_session()
        ref = session.query(PreauthTokenModel).get(token_id)
        if not ref:
            raise exception.NotFound('url not found')
        if ref.object_id != object_id or \
                        ref.action != action or \
                        ref.resource != resource:
            return False
        return True

