# Copyright 2012 OpenStack LLC
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
import uuid
import itertools
import copy
from datetime import datetime
from keystone.common import sql
from keystone import exception
from keystone import jio_policy
from oslo_serialization import jsonutils
from sqlalchemy.orm import load_only
from sqlalchemy import or_
from sqlalchemy import and_


class JioPolicyModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'jio_policy'
    attributes = ['id', 'project_id', 'created_at', 'deleted_at']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(255), nullable=False)
    project_id = sql.Column(sql.String(64), nullable=False)
    created_at = sql.Column(sql.DateTime, nullable=False)
    updated_at = sql.Column(sql.DateTime)
    deleted_at = sql.Column(sql.DateTime)
    policy_blob = sql.Column(sql.JsonBlob)


class PolicyActionResourceModel(sql.ModelBase):
    __tablename__ = 'policy_action_resource'
    attributes = ['policy_id', 'action_id', 'resource_id', 'effect']
    policy_id = sql.Column(sql.String(64), primary_key=True)
    action_id = sql.Column(sql.String(64), primary_key=True)
    resource_id = sql.Column(sql.String(64), primary_key=True)
    effect = sql.Column(sql.Boolean)


class ActionModel(sql.ModelBase):
    __tablename__ = 'action'
    attributes = ['id', 'action_name', 'service_type']
    id = sql.Column(sql.String(64), primary_key=True)
    action_name = sql.Column(sql.String(255))
    service_type = sql.Column(sql.String(255), nullable=False)


class ResourceModel(sql.ModelBase):
    __tablename__ = 'resource'
    attirbutes = ['id', 'resource_name', 'service_type']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(255), nullable=False)
    service_type = sql.Column(sql.String(255), nullable=False)


class PolicyUserGroupModel(sql.ModelBase):
    __tablename__ = 'policy_user_group_mapping'
    attributes = ['type', 'user_group_id', 'policy_id']
    type = sql.Column(sql.Enum('UserPolicy', 'GroupPolicy'), nullable=False,
                      primary_key=True)
    user_group_id = sql.Column(sql.String(64), nullable=False,
                               primary_key=True)
    policy_id = sql.Column(sql.String(64), nullable=False, primary_key=True)


class Policy(jio_policy.Driver):

    @classmethod
    def _get_service_name(cls, resource_name):
        ls = resource_name.split(':')
        if len(ls) < 5:
            raise exception.ValidationError(attribute='service name',
                                            target='resource')
        return ls[3]

    @sql.handle_conflicts(conflict_type='policy')
    def create_policy(self, project_id, policy_id, policy):
        ref = copy.deepcopy(policy)
        ref['id'] = policy_id

        name = policy.get('name', None)
        statement = policy.get('statement', None)

        created_at = datetime.utcnow()

        with sql.transaction() as session:
            session.add(JioPolicyModel(id=policy_id, name=name,
                        project_id=project_id, created_at=created_at,
                        updated_at=created_at,
                        policy_blob=jsonutils.dumps(ref)))
            for stmt in statement:
                action = stmt.get('action', None)
                effect = stmt.get('effect', None)
                resource = stmt.get('resource', None)
                if effect == 'allow':
                    effect = True
                elif effect == 'deny':
                    effect = False
                else:
                    raise exception.ValidationError(attribute='allow or deny',
                                                    target='effect')
                resource_ids = [uuid.uuid4().hex for i in range(len(resource))]
                try:
                    for pair in zip(resource_ids, resource):
                        session.add(ResourceModel(id=pair[0], name=pair[1],
                                    service_type=Policy._get_service_name(
                                        pair[1])))

                    for pair in itertools.product(action, resource_ids):
                        action_id = session.query(ActionModel).filter_by(
                                action_name=pair[0]).with_entities(
                                        ActionModel.id).one()[0]

                        session.add(
                            PolicyActionResourceModel(
                                policy_id=policy_id, action_id=action_id,
                                resource_id=pair[1], effect=effect))
                except sql.NotFound:
                    raise exception.ValidationError(
                            attribute='valid action', target='policy')
                except sql.DBReferenceError:
                    raise exception.ValidationError(
                            attribute='valid service name', target='resource')

        ref['attachment_count'] = 0
        ref['created_at'] = created_at
        ref['updated_at'] = created_at
        return ref

    def list_policies(self, project_id):
        session = sql.get_session()

        refs = session.query(JioPolicyModel).filter_by(project_id=project_id)\
            .with_entities(
                    JioPolicyModel.id, JioPolicyModel.name,
                    JioPolicyModel.created_at, JioPolicyModel.updated_at)
        ret = []
        attrs_to_return = ['id', 'name', 'created_at', 'deleted_at',
                           'attachment_count']
        for ref in refs:
            new_ref = {}
            for index, value in enumerate(ref):
                new_ref[attrs_to_return[index]] = value
            new_ref['attachment_count'] = int(self._find_attachment_count(
                session, new_ref['id']))
            ret.append(new_ref)
        return ret

    def _get_policy(self, session, policy_id):
        """Private method to get a policy model object (NOT a dictionary)."""
        ref = session.query(JioPolicyModel).get(policy_id)
        if not ref:
            raise exception.PolicyNotFound(policy_id=policy_id)
        return ref

    def _find_attachment_count(self, session, policy_id):
        return session.query(PolicyUserGroupModel).filter_by(
                policy_id=policy_id).count()

    def get_policy(self, policy_id):
        session = sql.get_session()
        count = self._find_attachment_count(session, policy_id)
        # TODO(ajayaa) Query for only required columns.
        ref = session.query(JioPolicyModel).get(policy_id)
        if not ref:
            raise exception.PolicyNotFound(policy_id=policy_id)
        ret = jsonutils.loads(ref.policy_blob)
        ret['created_at'] = ref.created_at
        ret['updated_at'] = ref.updated_at
        attachment_count = self._find_attachment_count(session, policy_id)
        ret['attachment_count'] = int(attachment_count)
        return ret

    @sql.handle_conflicts(conflict_type='policy')
    def update_policy(self, policy_id, policy):
        session = sql.get_session()
        service = 'image'

        # TODO(ajayaa) sql optimizations.
        with session.begin():
            ref = self._get_policy(session, policy_id)
            ref.name = policy.get('name')
            ref.updated_at = datetime.utcnow()
            policy_blob = jsonutils.loads(ref.policy_blob)
            policy_blob['name'] = ref.name
            if 'statement' in policy:
                statement = policy.get('statement')
                policy_blob['statement'] = statement
                policy_action_resource = session.query(
                        PolicyActionResourceModel).filter_by(
                                policy_id=ref.id).all()
                session.query(PolicyActionResourceModel).filter_by(
                        policy_id=ref.id).delete()
                for row in policy_action_resource:
                    session.query(ResourceModel).filter_by(
                            id=row.resource_id).delete()
                for stmt in statement:
                    action = stmt.get('action', None)
                    effect = stmt.get('effect', None)
                    resource = stmt.get('resource', None)
                    if effect == 'allow':
                        effect = True
                    elif effect == 'deny':
                        effect = False
                    else:
                        raise exception.ValidationError(attribute='allow or deny',
                                                        target='effect')
                    resource_ids = [uuid.uuid4().hex for i in range(len(resource))]
                    try:
                        for pair in zip(resource_ids, resource):
                            session.add(ResourceModel(id=pair[0], name=pair[1],
                                        service_type=Policy._get_service_name(
                                            pair[1])))

                        for pair in itertools.product(action, resource_ids):
                            action_id = session.query(ActionModel).filter_by(
                                    action_name=pair[0]).with_entities(
                                            ActionModel.id).one()[0]

                            session.add(
                                PolicyActionResourceModel(
                                    policy_id=policy_id, action_id=action_id,
                                    resource_id=pair[1], effect=effect))
                    except sql.NotFound:
                        raise exception.ValidationError(
                                attribute='valid action', target='policy')
                    except sql.DBReferenceError:
                        raise exception.ValidationError(
                                attribute='valid service name', target='resource')

            ref.policy_blob = jsonutils.dumps(policy_blob)
        return dict(policy_blob)

    def delete_policy(self, policy_id):
        session = sql.get_session()

        with session.begin():
            policy_ref = self._get_policy(session, policy_id)
            policy_action_resource = session.query(PolicyActionResourceModel).\
                filter_by(policy_id=policy_ref.id).all()
            session.query(PolicyActionResourceModel).filter_by(
                policy_id=policy_ref.id).delete()
            policy_user_group = session.query(PolicyUserGroupModel).filter_by(
                policy_id=policy_ref.id).all()
            for row in policy_action_resource:
                session.query(ResourceModel).filter_by(id=row.resource_id).\
                    delete()
            for row in policy_user_group:
                session.query(PolicyUserGroupModel).filter_by(
                    policy_id=row.id).delete()
            session.delete(policy_ref)

    def is_user_authorized(self, user_id, group_id, project_id, action, resource):
        session = sql.get_session()
        # query action id from action name in action table
        action_info = session.query(ActionModel.id).\
            filter(ActionModel.action_name == action).first()
        if action_info is None:
            raise exception.ActionNotFound(action=action)
        else:
            action_info = action_info[0]

        resource_direct = session.query(ResourceModel.id).\
            filter(ResourceModel.name == resource).first()
        resource_generic = resource[:resource.rfind(':')+1]+'*'
        resource_indirect = session.query(ResourceModel.id).\
            filter(ResourceModel.name == resource_generic).\
            first()

        if resource_direct is not None:
            resource_direct = resource_direct[0]

        if resource_indirect is not None:
            resource_indirect = resource_indirect[0]

        if resource_direct is None and resource_indirect is None:
            raise exception.ResourceNotFound(resource=resource)

        user_query = session.query(PolicyActionResourceModel.effect,
                                   PolicyUserGroupModel,
                                   JioPolicyModel)
        user_query = user_query.\
            filter(PolicyActionResourceModel.policy_id ==
                   PolicyUserGroupModel.policy_id)
        user_query = user_query.\
            filter(PolicyActionResourceModel.policy_id == JioPolicyModel.id)
        user_query = user_query.\
            filter(JioPolicyModel.project_id == project_id)
        user_query = user_query.\
            filter(PolicyActionResourceModel.action_id == action_info)
        user_query = user_query.\
            filter(PolicyUserGroupModel.user_group_id == user_id)
        user_query = user_query.\
            filter(
                   or_(
                       PolicyActionResourceModel.resource_id ==
                       resource_direct,
                       PolicyActionResourceModel.resource_id ==
                       resource_indirect
                          )
                  ).all()

        if group_id != []:
            group_query = session.query(PolicyActionResourceModel.effect,
                                        PolicyUserGroupModel,
                                        JioPolicyModel)
            group_query = group_query.\
                filter(PolicyActionResourceModel.policy_id ==
                       PolicyUserGroupModel.policy_id)
            group_query = group_query.\
                filter(PolicyActionResourceModel.policy_id ==
                       JioPolicyModel.id)
            group_query = group_query.\
                filter(JioPolicyModel.project_id == project_id)
            group_query = group_query.\
                filter(PolicyActionResourceModel.action_id ==
                       action_info)
            group_query = group_query.\
                filter(PolicyUserGroupModel.user_group_id.
                       in_(group_id))
            group_query = group_query.\
                filter(
                       or_(
                           PolicyActionResourceModel.resource_id ==
                           resource_direct,
                           PolicyActionResourceModel.resource_id ==
                           resource_indirect
                              )
                      ).all()
        else:
            group_query = None

        # add assert and debug prints

        is_authorized = True
        if user_query:
            for row in user_query:
                is_authorized = is_authorized and row[0]

        if group_query:
            for row in group_query:
                is_authorized = is_authorized and row[0]

        if not user_query and not group_query:
            is_authorized = False

        return is_authorized


    def _attach_policy_to_user_group(self, policy_id, user_group_id,
                                     type=None):
        session = sql.get_session()
        with session.begin():
            policy_ref = self._get_policy(session, policy_id)
            session.add(PolicyUserGroupModel(type=type, policy_id=policy_id,
                                             user_group_id=user_group_id))

    def _detach_policy_from_user_group(self, policy_id, user_group_id,
                                       type=None):
        session = sql.get_session()
        with session.begin():
            policy_ref = self._get_policy(session, policy_id)
            session.query(PolicyUserGroupModel).filter_by(
                user_group_id=user_group_id).filter_by(policy_id=policy_id).\
                filter_by(type=type).delete()

    def attach_policy_to_user(self, policy_id, user_id):
        self._attach_policy_to_user_group(policy_id, user_id,
                                          type='UserPolicy')

    def detach_policy_from_user(self, policy_id, user_id):
        self._detach_policy_from_user_group(policy_id, user_id,
                                            type='UserPolicy')

    def attach_policy_to_group(self, policy_id, group_id):
        self._attach_policy_to_user_group(policy_id, group_id,
                                          type='GroupPolicy')

    def detach_policy_from_group(self, policy_id, group_id):
        self._detach_policy_from_user_group(policy_id, group_id,
                                            type='GroupPolicy')

    def list_actions(self, hints):
        session = sql.get_session()
        query = session.query(ActionModel).all()
        refs = sql.filter_limit_query(ActionModel, query, hints)
        ret = []
        attrs_to_return = ['id', 'action_name', 'service_type']
        for ref in refs:
            new_ref = {}
            for r in attrs_to_return:
                new_ref[r] = ref.get(r)
                ret.append(new_ref)
        return ret


def create_action(action_id, action_name, service_type):
    ref = dict()
    ref['id'] = action_id
    ref['name'] = action_name
    ref['service_type'] = service_type
    session = sql.get_session()
    with session.begin():
	try:
            session.add(ActionModel(id=action_id, action_name=action_name, service_type=service_type))
	except sql.DBReferenceError:
            raise exception.ValidationError(attribute='valid service name', target='resource')
    return ref
