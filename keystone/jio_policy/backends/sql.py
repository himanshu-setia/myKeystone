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
from keystone.policy.backends import rules


class JioPolicyModel(sql.ModelBase):
    __tablename__ = 'jio_policy'
    attributes = ['id', 'project_id', 'created_at', 'deleted_at']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    project_id = sql.Column(sql.String(64), nullable=False)
    created_at = sql.Column(sql.DateTime, nullable=False)
    updated_at = sql.Column(sql.DateTime)
    deleted_at = sql.Column(sql.DateTime)

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
    action_name = sql.Column(sql.String(64))
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
    type = sql.Column(
        sql.Enum('UserPolicy', 'GroupPolicy'), nullable=False, primary_key=True)
    user_group_id = sql.Column(sql.String(64), nullable=False, primary_key=True)
    policy_id = sql.Column(sql.String(64), nullable=False, primary_key=True)


class Policy(rules.Policy):

    @sql.handle_conflicts(conflict_type='policy')
    def create_policy(self, service, project_id, policy_id, policy):

        ref = copy.deepcopy(policy)
        ref['id'] = policy_id
        name = policy.pop('name', None)
        if name is None:
            raise exception.ValidationError(attribute='name', target='policy')
        statement = policy.pop('statement', None)
        if statement is None:
            raise exception.ValidationError(attribute='statement', target='policy')

        action_name = statement[0].get('action')[0]
        with sql.transaction() as session:
            action_id = session.query(ActionModel.id).filter(ActionModel.action_name==action_name).one()

        created_at = datetime.utcnow()
        with sql.transaction() as session:
            session.add(JioPolicyModel(id=policy_id,name=name,
                project_id=project_id, created_at=created_at))
            for stmt in statement:
                action = stmt.pop('action', None)
                if type(action) != list:
                    action = [action]
                effect = stmt.pop('effect', None)
                resource = stmt.pop('resource', None)
                if type(resource) != list:
                    resource = [resource]
                if effect == 'allow':
                    effect = True
                else:
                    effect = False
                resource_ids = [uuid.uuid4().hex for i in range(len(resource))]
                for pair in zip(resource_ids, resource):
                    session.add(ResourceModel(id=pair[0], name=pair[1],
                        service_type=service))

                for pair in itertools.product(action, resource_ids):
                    session.add(PolicyActionResourceModel(
                       policy_id=policy_id, action_id=session.query(ActionModel.id).filter(ActionModel.action_name==pair[0]).one()[0],
                       resource_id=pair[1], effect=effect))
        return ref

    def list_policies(self):
        session = sql.get_session()

        refs = session.query(PolicyModel).all()
        return [ref.to_dict() for ref in refs]

    def _get_policy(self, session, policy_id):
        """Private method to get a policy model object (NOT a dictionary)."""
        ref = session.query(JioPolicyModel).get(policy_id)
        if not ref:
            raise exception.PolicyNotFound(policy_id=policy_id)
        return ref

    def get_policy(self, policy_id):
        session = sql.get_session()

        return self._get_policy(session, policy_id).to_dict()

    @sql.handle_conflicts(conflict_type='policy')
    def update_policy(self, policy_id, policy):
        session = sql.get_session()

        with session.begin():
            ref = self._get_policy(session, policy_id)
            old_dict = ref.to_dict()
            old_dict.update(policy)
            new_policy = PolicyModel.from_dict(old_dict)
            ref.blob = new_policy.blob
            ref.type = new_policy.type
            ref.extra = new_policy.extra

        return ref.to_dict()

    def delete_policy(self, policy_id):
        session = sql.get_session()

        with session.begin():
            policy_ref = self._get_policy(session, policy_id)
            policy_action_resource = session.query(PolicyActionResourceModel).filter_by(policy_id=policy_ref.id).all()
            session.query(PolicyActionResourceModel).filter_by(policy_id=policy_ref.id).delete()
            policy_user_group = session.query(PolicyUserGroupModel).filter_by(policy_id=policy_ref.id).all()
            for row in policy_action_resource:
                session.query(ResourceModel).filter_by(id=row.resource_id).delete()
            for row in policy_user_group:
                session.query(PolicyUserGroupModel).filter_by(policy_id=row.id).delete()
            session.delete(policy_ref)

    def _attach_policy_to_user_group(self, policy_id, user_group_id,
            type=None):
        session = sql.get_session()
        with session.begin():
            policy_ref = self._get_policy(session, policy_id)
            session.add(PolicyUserGroupModel(type=type, policy_id=
                policy_id, user_group_id=user_group_id))

    def _detach_policy_from_user_group(self, policy_id, user_group_id,
            type=None):
        session = sql.get_session()
        with session.begin():
            policy_ref = self._get_policy(session, policy_id)
            session.query(PolicyUserGroupModel).filter_by(
                    user_group_id=user_group_id).filter_by(policy_id=policy_id
                    ).filter_by(type=type).delete()

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
