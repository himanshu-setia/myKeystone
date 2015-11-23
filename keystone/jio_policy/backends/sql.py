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

from keystone.common import sql
from keystone import exception
from keystone.policy.backends import rules


class JioPolicyModel(sql.ModelBase):
    __tablename__ = 'jio_policy'
    attributes = ['id', 'project_id', 'created_at', 'deleted_at']
    id = sql.Column(sql.String(64), primary_key=True)
    project_id = sql.Column(sql.String(64), nullable=False)
    created_at = sql.Column(sql.DateTime, nullable=False)
    deleted_at = sql.Column(sql.DateTime, nullable=False)

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
    resource_name = sql.Column(sql.String(255), nullable=False)
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
    def create_policy(self, policy_id, policy):
        session = sql.get_session()

        ref = policy
        with session.begin():
            ref = JioPolicyModel(
            session.add(ref))

        return ref

    def list_policies(self):
        session = sql.get_session()

        refs = session.query(PolicyModel).all()
        return [ref.to_dict() for ref in refs]

    def _get_policy(self, session, policy_id):
        """Private method to get a policy model object (NOT a dictionary)."""
        ref = session.query(PolicyModel).get(policy_id)
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
            ref = self._get_policy(session, policy_id)
            session.delete(ref)
