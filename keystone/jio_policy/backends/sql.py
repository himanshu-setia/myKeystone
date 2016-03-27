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
from keystone.common import dependency
from keystone.common import sql
from keystone import exception
from keystone import jio_policy
from oslo_serialization import jsonutils
from sqlalchemy.orm import load_only
from sqlalchemy import or_
from sqlalchemy import and_
from sqlalchemy.orm import relationship

iam_pre_format = 'jrn:jcs'

class JioPolicyModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'jio_policy'
    attributes = ['id', 'account_id', 'created_at']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(255), nullable=False)
    account_id = sql.Column(sql.String(64), nullable=False)
    type = sql.Column(sql.Enum('UserBased', 'ResourceBased'), nullable=False)
    created_at = sql.Column(sql.DateTime, nullable=False)
    updated_at = sql.Column(sql.DateTime)
    policy_blob = sql.Column(sql.JsonBlob)
    hidden = sql.Column(sql.Boolean, default=False, nullable=True)

class PolicyActionResourceModel(sql.ModelBase):
    __tablename__ = 'policy_action_resource'
    attributes = ['policy_id', 'action_id', 'resource_id', 'effect']
    policy_id = sql.Column(sql.String(64), sql.ForeignKey('jio_policy.id'), primary_key=True)
    action_id = sql.Column(sql.String(64), primary_key=True)
    resource_id = sql.Column(sql.String(64), primary_key=True)
    effect = sql.Column(sql.Boolean)


class ActionModel(sql.ModelBase):
    __tablename__ = 'action'
    attributes = ['id', 'action_name', 'service_type']
    id = sql.Column(sql.String(64), primary_key=True)
    action_name = sql.Column(sql.String(255))
    service_type = sql.Column(sql.String(255), nullable=False)


class ResourceTypeModel(sql.ModelBase):
    __tablename__ = 'resource_type'
    attributes = ['id', 'name', 'service_type']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(255), nullable=False)
    service_type = sql.Column(sql.String(255), nullable=False)


class ResourceModel(sql.ModelBase):
    __tablename__ = 'resource'
    attributes = ['id', 'name', 'service_type']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(255), nullable=False)
    service_type = sql.Column(sql.String(255), nullable=False)


class ActionResourceMappingModel(sql.ModelBase):
    __tablename__ = 'action_resource_type_mapping'
    attributes = ['action_id', 'resource_type_id']
    action_id = sql.Column(sql.String(64),
                    sql.ForeignKey('action.id'),
                    primary_key=True)
    resource_type_id = sql.Column(sql.String(64),
                  sql.ForeignKey('resource_type.id'),
                  primary_key=True)


class PolicyUserGroupModel(sql.ModelBase):
    __tablename__ = 'policy_user_group_mapping'
    attributes = ['type', 'user_group_id', 'policy_id']
    type = sql.Column(sql.Enum('UserPolicy', 'GroupPolicy'), nullable=False,
                      primary_key=True)
    user_group_id = sql.Column(sql.String(64), nullable=False,
                               primary_key=True)
    policy_id = sql.Column(sql.String(64), sql.ForeignKey('jio_policy.id'),nullable=False, primary_key=True)


class PolicyActionPrincipleModel(sql.ModelBase):
    __tablename__ = 'policy_action_principle'
    attributes = ['policy_id', 'action_id', 'principle_name', 'principle_type', 'principle_acc_id', 'effect']
    policy_id = sql.Column(sql.String(64), sql.ForeignKey('jio_policy.id'), primary_key=True)
    action_id = sql.Column(sql.String(64), sql.ForeignKey('action.id'), primary_key=True)
    principle_acc_id = sql.Column(sql.String(64),nullable=False)
    principle_name = sql.Column(sql.String(64), primary_key=True)
    principle_type = sql.Column(sql.Enum('User', 'Group', '*'), nullable=False)
    effect = sql.Column(sql.Boolean)


class PolicyResourceModel(sql.ModelBase):
    __tablename__ = 'policy_resource_mapping'
    attributes = ['resource_id', 'policy_id']
    resource_id = sql.Column(sql.String(64), sql.ForeignKey('resource.id'),
                               primary_key=True)
    policy_id = sql.Column(sql.String(64), sql.ForeignKey('jio_policy.id'), primary_key=True)
    resource = relationship("ResourceModel")

@dependency.requires('identity_api','resource_api')
class Policy(jio_policy.Driver):

    @classmethod
    def _get_service_name(cls, resource_name):
        ls = resource_name.split(':')
        if len(ls) < 3:
            raise exception.ValidationError(attribute='service name',
                                            target='resource')
        return ls[2]

    @classmethod
    def _get_action_service_name(cls, action_name):
        ls = action_name.split(':')
        if len(ls) < 3:
            raise exception.ValidationError(attribute='service name',
                                            target='action')
        return ls[2]

    @classmethod
    def _get_resource_type(cls, resource):
        ls = resource.split(':')
        if len(ls) < 5:
              return None
        return str(ls[4])

    @classmethod
    def _get_principle_list(cls, principle):
        ls = principle.split(':')
        if len(ls) < 4:
            raise exception.ValidationError(attribute='valid prefix(jrn:jcs:iam:AccountId)',
                                            target='principle')
        iam_prefix = ':'.join(ls[:2])
        if iam_prefix != iam_pre_format:
            raise exception.ValidationError(attribute='valid prefix(jrn:jcs)',
                                            target='principle')

        if ls[2] != 'iam':
            raise exception.ValidationError(attribute='valid service name(iam)',
                                            target='principle')
        return ls

    @classmethod
    def _get_resource_list(cls, resource):
        ls = resource.split(':')
        return ls

    @sql.handle_conflicts(conflict_message='Policy name already exist')
    def create_policy(self, account_id, policy_id, policy, hidden=False, service=False):
        ref = copy.deepcopy(policy)
        ref['id'] = policy_id
        name = policy.get('name', None)
        statement = policy.get('statement', None)
        created_at = datetime.utcnow()

        with sql.transaction() as session:
            session.add(JioPolicyModel(id=policy_id, name=name,
                        account_id=account_id, type='UserBased',
                        created_at=created_at,
                        updated_at=created_at,
                        hidden=hidden,
                        policy_blob=jsonutils.dumps(ref)))
            for stmt in statement:
                action = stmt.get('action', None)
                effect = stmt.get('effect', None)
                resource = stmt.get('resource', None)

                # Autofill account id in resource
                for index, item in enumerate(resource):
                    if len(item.split(':')) > 4 and item.split(':')[3]=='':
                        var=item.split(':')
                        var[3]=account_id
                        resource[index]=':'.join(var)

                # Assumption account_id == domain_id == project_id
                if effect == 'allow':
                    effect = True
                elif effect == 'deny':
                    effect = False
                else:
                    raise exception.ValidationError(attribute='allow or deny',
                                                    target='effect')
                resource_ids = [uuid.uuid4().hex for i in range(len(resource))]
                try:
                    zip_resource = zip(resource_ids, resource)

                    #For RBP,same resource will be used in UBP, so these resources will be
                    #redundant, need to remove them
                    for pair in zip_resource:
                        resource = pair[1].split(':')
                        resource[3] = account_id
                        res_name = ':'.join(resource)
                        session.add(ResourceModel(id=pair[0], name=res_name,
                                    service_type=Policy._get_service_name(
                                        pair[1])))

                    for pair in itertools.product(action, zip_resource):
                        is_cross_account_access = False
                        resource = Policy._get_resource_list(pair[1][1])
                        res_acc_id = resource[3]

                        if res_acc_id != account_id and service == False:
                            #LOG.debug('Cross Account Policy')

                            resource = session.query(ResourceModel.id).\
                                filter(ResourceModel.name == pair[1][1]).all()

                            resource_ids = [res[0] for res in resource]
                            policy_ids = session.query(JioPolicyModel).join(PolicyResourceModel)\
                                 .filter(PolicyResourceModel.resource_id.in_(resource_ids))\
                                 .filter(JioPolicyModel.account_id == res_acc_id)\
                                 .filter(JioPolicyModel.type == 'ResourceBased')\
                                 .with_entities(JioPolicyModel.id).all()

                            for policy in policy_ids:
                                id = policy[0]
                                effect = session.query(PolicyActionPrincipleModel).join(ActionModel)\
                                             .filter(PolicyActionPrincipleModel.policy_id == id).filter(ActionModel.action_name == pair[0])\
                                             .filter(PolicyActionPrincipleModel.principle_acc_id == account_id)\
                                             .with_entities(PolicyActionPrincipleModel.effect).all()

                                effect_list = [eff[0] for eff in effect]

                                for effect in effect_list:
                                    if not effect:
                                        is_cross_account_access = False
                                        break
                                    else:
                                        is_cross_account_access = True

                            if not is_cross_account_access:
                                raise exception.Forbidden(message='Resource Based Policy does not exist')

                        #check if action is allowed in resource type
                        action_id = session.query(ActionModel).filter_by(
                                action_name=pair[0]).with_entities(
                                        ActionModel.id).one()[0]
                        resource_type = Policy._get_resource_type(pair[1][1])
                        if resource_type is not None and resource_type != '*' and self.is_action_resource_type_allowed(session, pair[0], resource_type) is False:
                             raise exception.ValidationError(
                                     attribute='valid resource type', target='resource')

                        resource_id = pair[1][0]

                        session.add(
                            PolicyActionResourceModel(
                                policy_id=policy_id, action_id=action_id,
                                resource_id=resource_id, effect=effect))


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

    @sql.handle_conflicts(conflict_message='Policy Name already exist')
    def create_resource_based_policy(self, account_id, policy_id, policy):
        ref = copy.deepcopy(policy)
        ref['id'] = policy_id
        name = policy.get('name', None)
        statement = policy.get('statement', None)
        created_at = datetime.utcnow()

        with sql.transaction() as session:
            session.add(JioPolicyModel(id=policy_id, name=name,
                        type='ResourceBased',
                        account_id=account_id,
                        created_at=created_at,
                        updated_at=created_at,
                        policy_blob=jsonutils.dumps(ref)))
            for stmt in statement:
                action = stmt.get('action', None)
                effect = stmt.get('effect', None)
                principle = stmt.get('principle', None)

                if effect == 'allow':
                    effect = True
                elif effect == 'deny':
                    effect = False
                else:
                    raise exception.ValidationError(attribute='allow or deny',
                                                    target='effect')
                try:

                    for pair in itertools.product(action, principle):
                        action_service_name = self._get_action_service_name(pair[0])
                        if action_service_name != 'dss':
                             raise exception.ValidationError(
                                     attribute='valid service name', target='action')

                        action_id = session.query(ActionModel).filter_by(
                                action_name=pair[0]).with_entities(
                                        ActionModel.id).one()[0]

                        principle_list = Policy._get_principle_list(pair[1])
                        principle_name = '*' if len(principle_list) < 6 else principle_list[5]
                        principle_type = 'None' if len(principle_list) < 5 else principle_list[4]
                        #For principle as AccId, both the type and id of principle will be NULL
                        #as we need to only give permission to the account owner.
                        if principle_type == 'None':
                            principle_name = 'None'
                        if principle_type is not 'None' and principle_type not in ['*','User','Group']:
                             raise exception.ValidationError(
                                     attribute='valid principle type', target='principle')

                        principle_acc_id = principle_list[3]
                        self.resource_api.get_account(principle_acc_id)

                        if principle_acc_id == account_id:
                             msg = ('Cannot create Resource Based Policy for caller\'s account.'+\
                             ' Resource based policies are only for cross account access')
                             raise exception.ValidationError(message=msg)
                        if principle_type == 'User' and principle_name !='*':
                            user = self.identity_api.get_user_by_name(principle_name, principle_acc_id)
                        elif principle_type == 'Group' and principle_name !='*':
                            group = self.identity_api.get_group_by_name(principle_name, principle_acc_id)

                        session.add(
                            PolicyActionPrincipleModel(
                                policy_id=policy_id, action_id=action_id,principle_acc_id=principle_acc_id,
                                principle_name=principle_name, principle_type=principle_type ,effect=effect))

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

    def list_policies(self, account_id):
        session = sql.get_session()

        refs = session.query(JioPolicyModel).filter_by(account_id=account_id)\
            .filter_by(type='UserBased').filter_by(hidden=False).with_entities(
                    JioPolicyModel.id, JioPolicyModel.name,
                    JioPolicyModel.created_at)
        ret = []
        attrs_to_return = ['id', 'name', 'created_at', 'attachment_count']
        for ref in refs:
            new_ref = {}
            for index, value in enumerate(ref):
                new_ref[attrs_to_return[index]] = value
            new_ref['attachment_count'] = int(self._find_attachment_count(
                session, new_ref['id']))
	    #The logic to find the users anf groups for the policy should be ideally be
            #done in one pass through the table. Currently its done in 2 passes to keep
            #it separate for groups and users, but for optimization can be done in 1 pass.
            new_ref['attached_groups'] = self.count_groups_for_policy(new_ref['id'])
            new_ref['attached_users'] = self.count_users_for_policy(new_ref['id'])
            ret.append(new_ref)
        return ret

    def list_resource_based_policies(self, account_id):
        session = sql.get_session()

        refs = session.query(JioPolicyModel).filter_by(account_id=account_id)\
            .filter_by(type='ResourceBased').with_entities(
                    JioPolicyModel.id, JioPolicyModel.name,
                    JioPolicyModel.created_at)
        ret = []
        attrs_to_return = ['id', 'name', 'created_at', 'attachment_count']
        for ref in refs:
            new_ref = {}
            for index, value in enumerate(ref):
                new_ref[attrs_to_return[index]] = value
            new_ref['attachment_count'] = int(self._find_attached_resources_count(
                session, new_ref['id']))
            ret.append(new_ref)
        return ret

    def count_groups_for_policy(self,policy_id):
        session = sql.get_session()

        query = session.query(PolicyUserGroupModel)
        query = query.filter(PolicyUserGroupModel.policy_id == policy_id)
        query = query.filter(PolicyUserGroupModel.type == 'GroupPolicy')

        return query.count()

    def count_users_for_policy(self,policy_id):
        session = sql.get_session()

        query = session.query(PolicyUserGroupModel)
        query = query.filter(PolicyUserGroupModel.policy_id == policy_id)
        query = query.filter(PolicyUserGroupModel.type == 'UserPolicy')

        return query.count()

    def _get_policy_account(session, policy_id):
        session = sql.get_session()
        """Private method to get a policy model object (NOT a dictionary)."""
        ref = session.query(JioPolicyModel).get(policy_id)
        if not ref:
            raise exception.PolicyNotFound(policy_id=policy_id)
        return ref.account_id

    def _get_policy(self, session, policy_id):
        """Private method to get a policy model object (NOT a dictionary)."""
        ref = session.query(JioPolicyModel).get(policy_id)
        if not ref:
            raise exception.PolicyNotFound(policy_id=policy_id)
        return ref

    def _find_attachment_count(self, session, policy_id):
        return session.query(PolicyUserGroupModel).filter_by(
                policy_id=policy_id).count()

    def _find_attached_resources_count(self, session, policy_id):
        return session.query(PolicyResourceModel).filter_by(
                policy_id=policy_id).count()

    def get_policy(self, policy_id):
        session = sql.get_session()
        count = self._find_attachment_count(session, policy_id)
        # TODO(roopali) Query for only required columns.
        ref = session.query(JioPolicyModel).get(policy_id)
        if not ref or ref.type != 'UserBased' or ref.hidden:
            raise exception.PolicyNotFound(policy_id=policy_id)
        ret = jsonutils.loads(ref.policy_blob)
        ret['created_at'] = ref.created_at
        ret['updated_at'] = ref.updated_at
        attachment_count = self._find_attachment_count(session, policy_id)
        ret['attachment_count'] = int(attachment_count)
        return ret

    def get_policies_count_in_account(self, account_id):
        session = sql.get_session()
        count = session.query(JioPolicyModel).filter_by(account_id=account_id).count()
        return count

    #Function returns policy count for user in account
    def get_user_attach_policy_count_in_account(self, user_id):
        session = sql.get_session()
        query = session.query(PolicyUserGroupModel)
        query = query.filter(PolicyUserGroupModel.user_group_id == user_id)
        query = query.filter(PolicyUserGroupModel.type == 'UserPolicy')
        return query.count()

    def get_group_attach_policy_count_in_account(self, group_id):
        session = sql.get_session()
        query = session.query(PolicyUserGroupModel)
        query = query.filter(PolicyUserGroupModel.user_group_id == group_id)
        query = query.filter(PolicyUserGroupModel.type == 'GroupPolicy')
        count = query.count()
        return count

    def get_resource_based_policy(self, policy_id):
        session = sql.get_session()
        ref = session.query(JioPolicyModel).get(policy_id)
        if not ref or ref.type != 'ResourceBased':
            raise exception.PolicyNotFound(policy_id=policy_id)
        ret = jsonutils.loads(ref.policy_blob)
        ret['created_at'] = ref.created_at
        ret['updated_at'] = ref.updated_at
        attachment_count = self._find_attached_resources_count(session, policy_id)
        ret['attachment_count'] = int(attachment_count)
        return ret

    @sql.handle_conflicts(conflict_message='Policy conflict')
    def update_policy(self, policy_id, policy):
        session = sql.get_session()
        service = 'image'

        # TODO(roopali) sql optimizations.
        with session.begin():
            ref = self._get_policy(session, policy_id)
            if ref.hidden:
                raise exception.PolicyNotFound(policy_id=policy_id)
            ref.name = policy.get('name')
            ref.updated_at = datetime.utcnow()
            policy_blob = jsonutils.loads(ref.policy_blob)
            policy_blob['name'] = ref.name
            if 'statement' in policy:
                statement = policy.get('statement')
                policy_blob['statement'] = copy.deepcopy(statement)
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

                    # Autofill account id in resource
                    for index, item in enumerate(resource):
                        if len(item.split(':')) > 4 and item.split(':')[3]=='':
                            var=item.split(':')
                            var[3]=account_id
                            resource[index]=':'.join(var)

                    if effect == 'allow':
                        effect = True
                    elif effect == 'deny':
                        effect = False
                    else:
                        raise exception.ValidationError(attribute='allow or deny',
                                                        target='effect')
                    resource_ids = [uuid.uuid4().hex for i in range(len(resource))]
                    try:
                        zip_resource = zip(resource_ids, resource)
                        for pair in zip_resource:
                            session.add(ResourceModel(id=pair[0], name=pair[1],
                                        service_type=Policy._get_service_name(
                                            pair[1])))

                        for pair in itertools.product(action, zip_resource):
                            action_id = session.query(ActionModel).filter_by(
                                    action_name=pair[0]).with_entities(
                                            ActionModel.id).one()[0]
                            resource_type = Policy._get_resource_type(pair[1][1])
                            if resource_type is not None and resource_type != '*' and self.is_action_resource_type_allowed(session, pair[0], resource_type) is False:
                                raise exception.ValidationError(
                                       attribute='valid resource type', target='resource')

                            session.add(
                                PolicyActionResourceModel(
                                    policy_id=policy_id, action_id=action_id,
                                    resource_id=pair[1][0], effect=effect))
                    except sql.NotFound:
                        raise exception.ValidationError(
                                attribute='valid action', target='policy')
                    except sql.DBReferenceError:
                        raise exception.ValidationError(
                                attribute='valid service name', target='resource')

            ref.policy_blob = jsonutils.dumps(policy_blob)
        return dict(policy_blob)


    @sql.handle_conflicts(conflict_message='Policy conflict')
    def update_resource_based_policy(self, policy_id, policy):
        session = sql.get_session()
        with session.begin():
            ref = self._get_policy(session, policy_id)
            ref.name = policy.get('name')
            ref.updated_at = datetime.utcnow()
            policy_blob = jsonutils.loads(ref.policy_blob)
            policy_blob['name'] = ref.name
            if 'statement' in policy:
                statement = policy.get('statement')
                policy_blob['statement'] = statement

                session.query(PolicyActionPrincipleModel).filter_by(
                        policy_id=ref.id).delete()

                for stmt in statement:
                    action = stmt.get('action', None)
                    effect = stmt.get('effect', None)
                    principle = stmt.get('principle', None)
                    if effect == 'allow':
                        effect = True
                    elif effect == 'deny':
                        effect = False
                    else:
                        raise exception.ValidationError(attribute='allow or deny',
                                                        target='effect')
                    try:

                        for pair in itertools.product(action, principle):
                            action_service_name = self._get_action_service_name(pair[0])
                            if action_service_name != 'dss':
                               raise exception.ValidationError(
                                     attribute='valid service name', target='action')

                            #check if action is allowed in resource type
                            action_id = session.query(ActionModel).filter_by(
                                    action_name=pair[0]).with_entities(
                                            ActionModel.id).one()[0]

                            principle_list = Policy._get_principle_list(pair[1])
                            principle_name = '*' if len(principle_list) < 6 else principle_list[5]
                            principle_type = 'None' if len(principle_list) < 5 else principle_list[4]
                            #For principle as AccId, both the type and id of principle will be NULL
                            #as we need to only give permission to the account owner.
                            if principle_type == 'None':
                                principle_name = 'None'
                            if principle_type is not 'None' and principle_type not in ['*','User','Group']:
                                 raise exception.ValidationError(
                                     attribute='valid principle type', target='principle')

                            principle_acc_id = principle_list[3]
                            self.resource_api.get_account(principle_acc_id)

                            if principle_type == 'User' and principle_name !='*':
                                user = self.identity_api.get_user_by_name(principle_name, principle_acc_id)
                            elif principle_type == 'Group' and principle_name !='*':
                                group = self.identity_api.get_group_by_name(principle_name, principle_acc_id)

                            session.add(
                                PolicyActionPrincipleModel(
                                    policy_id=policy_id, action_id=action_id,principle_acc_id=principle_acc_id,
                                    principle_name=principle_name, principle_type=principle_type ,effect=effect))

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
            if policy_ref.hidden or policy_ref.type != 'UserBased':
                raise exception.PolicyNotFound(policy_id=policy_id)
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
                   policy_id=row.policy_id).delete()
            session.delete(policy_ref)

    def get_group_policies(self,groupid):
        session = sql.get_session()

        group_query = session.query(JioPolicyModel,PolicyUserGroupModel)
        group_query = group_query.filter(PolicyUserGroupModel.policy_id==JioPolicyModel.id)
        group_query = group_query.filter(PolicyUserGroupModel.user_group_id==groupid)
        group_query = group_query.filter(PolicyUserGroupModel.type == 'GroupPolicy')
        group_query = group_query.filter(JioPolicyModel.hidden != True).all()
        #if group_query.count() == 0):
          #  return

        if not group_query:
            return False
        policy_list = []
        for row in group_query:
            policy = dict()
            policy['policy_id'] = row[0].id
            policy['policy_name'] = row[0].name
            policy_list.append(policy)

        return policy_list

    def get_user_policies(self,userid):
        session = sql.get_session()

        group_query = session.query(JioPolicyModel,PolicyUserGroupModel)
        group_query = group_query.filter(PolicyUserGroupModel.policy_id==JioPolicyModel.id)
        group_query = group_query.filter(PolicyUserGroupModel.user_group_id==userid)
        group_query = group_query.filter(PolicyUserGroupModel.type == 'UserPolicy')
        group_query = group_query.filter(JioPolicyModel.hidden != True).all()
        #if group_query.count() == 0:
          #  return
        if not group_query:
            return False
        policy_list = []
        for row in group_query:
            policy = dict()
            policy['policy_id'] = row[0].id
            policy['policy_name'] = row[0].name
            policy_list.append(policy)

        return policy_list

    def delete_resource_based_policy(self, policy_id):
        session = sql.get_session()

        with session.begin():
            policy_ref = self._get_policy(session, policy_id)
            if policy_ref.hidden or policy_ref.type != 'ResourceBased':
                raise exception.PolicyNotFound(policy_id=policy_id)

            session.query(PolicyActionPrincipleModel).filter_by(
                policy_id=policy_ref.id).delete()
            session.query(PolicyResourceModel).filter_by(
                policy_id=policy_ref.id).delete()

            session.delete(policy_ref)


    def is_cross_account_access_auth(self, user_id, group_ids, user_acc_id, res_id, action, is_impl_allow):
        session = sql.get_session()
        if len(res_id.split(':')) < 6:
            raise exception.ResourceNotFound(resource=res_id)
        resource = Policy._get_resource_list(res_id)
        res_acc_id = resource[3]
        if len(res_acc_id) == 32:
            res_acc_id = res_acc_id[-12:]
            resource[3] = res_acc_id[-12:]
            res_id = ':'.join(resource)
        elif len(res_acc_id) != 12:
            raise exception.NotFound("AccountId in resource %s cannot be found."%resource)


        resource = session.query(ResourceModel.id).\
            filter(ResourceModel.name == res_id).all()

        resource_ids = [x[0] for x in resource]
        policy_ids = session.query(JioPolicyModel).join(PolicyResourceModel)\
                        .filter(PolicyResourceModel.resource_id.in_(resource_ids))\
                        .filter(JioPolicyModel.account_id == res_acc_id)\
                        .filter(JioPolicyModel.type == 'ResourceBased')\
                        .with_entities(JioPolicyModel.id).all()

        policy_exists = False
        is_authorized = True
        for policy in policy_ids:
            policy_id = policy[0]
            result_list = session.query(PolicyActionPrincipleModel).join(ActionModel)\
                         .filter(PolicyActionPrincipleModel.policy_id == policy_id).filter(ActionModel.action_name == action).all()
            for result in result_list:
                if result:
                    user = self.identity_api.get_user(user_id)
                    user_name = user['name']
                    if result.principle_type == 'None':
                        if user['type'] == 'root':
                            policy_exists = True
                            is_authorized = result.effect
                    if result.principle_type in ['*', 'User'] and result.principle_name in ['*',user_name]:
                        if user['account_id'] == result.principle_acc_id:
                            policy_exists = True
                            is_authorized = result.effect
                    if result.principle_type in ['*', 'Group']:
                        principle = self.identity_api.get_group_by_name(result.principle_name, result.principle_acc_id)
                        principle_id = principle['id']
                        if ((result.principle_name == '*' and len(group_ids) > 0) or (principle_id in group_ids)):
                            if user['account_id'] == result.principle_acc_id:
                                policy_exists = True
                                is_authorized = result.effect

                if is_authorized == False:
                    return False

        if policy_exists is True:
            return True
        else:
            return is_impl_allow

    def get_action_list(self, action):
        session = sql.get_session()
        # query action id from action name in action table
        action_direct = session.query(ActionModel.id).\
            filter(ActionModel.action_name == action).all()
        if action_direct==[]:
            raise exception.ActionNotFound(action=action)

        action_generic = list()
        action_generic.append(action)
        action_generic.append('jrn:jcs:*')
        if len(action.split(':')) > 3:
            action_generic.append('jrn:jcs:'+action.split(':')[2]+':*')
        action_list = session.query(ActionModel.id).\
            filter(ActionModel.action_name.in_(action_generic)).all()

        # converts a list of tuples to a list
        j = 0
        for i in action_list:
            action_list[j] = i[0]
            j = j+1

        return action_list

    def get_resource_list(self,resource):
        session = sql.get_session()

        resource_generic = list()
        resource_generic.append(resource)
        resource_generic.append(resource[:resource.rfind(':')+1]+'*')
        if len(resource.split(':')) > 3:
            resource_generic.append('jrn:jcs:'+resource.split(':')[2]+':*')
        if len(resource.split(':')) > 4:
            resource_generic.append('jrn:jcs:*:'+resource.split(':')[3]+':*')
            resource_generic.append('jrn:jcs:'+resource.split(':')[2]+':'+
                                    resource.split(':')[3]+':*')

        resource_list = session.query(ResourceModel.id).\
            filter(ResourceModel.name.in_(resource_generic)).\
            all()

        # converts a list of tuples to a list

        j = 0
        for i in resource_list:
            resource_list[j] = i[0]
            j = j+1

        return resource_list

    def is_user_authorized(self, user_id, group_id, account_id, action, resource, is_implicit_allow):
        session = sql.get_session()
        # resource name must have 5 separators (:) e.g.
        # 'jrn:jcs:service:tenantid:rtype:res' is a valid resource name
        # providing tenantid is optional for a service
        # but the format should be maintained
        if len(resource.split(':')) < 6:
            raise exception.ResourceNotFound(resource=resource)
        # in case tenantid is not present in resource, update it
        resource_acc_id = resource.split(':')[3].strip()
        if resource_acc_id == '':
            var = resource.split(':')
            var[3] = account_id
            resource = ':'.join(var)
        elif len(resource_acc_id) == 32:
            var = resource.split(':')
            var[3] = resource_acc_id[-12:]
            resource = ':'.join(var)
        elif len(resource_acc_id) != 12:
            raise exception.NotFound("AccountId in resource %s cannot be found."%resource)

        if len(action.split(':')) < 4:
            raise exception.ActionNotFound(action=action)
        if action.split(':')[3] == '*':
            raise exception.ActionNotFound(action=action)

        #if action_direct == [] and action_indirect == []:
        #    raise exception.ActionNotFound(action=action)
        action_list = self.get_action_list(action)
        resource_list = self.get_resource_list(resource)

        if resource_list == []:
            return is_implicit_allow
            #raise exception.ResourceNotFound(resource=resource)
        group_id.append(user_id)
        user_group_query = session.query(PolicyActionResourceModel.effect).join(JioPolicyModel).join(PolicyUserGroupModel)
        user_group_query = user_group_query.\
            filter(JioPolicyModel.account_id == account_id)
        user_group_query = user_group_query.\
            filter(PolicyUserGroupModel.user_group_id.in_(group_id))
        if action_list != []:
            user_group_query = user_group_query.\
                filter(PolicyActionResourceModel.action_id.in_(action_list))
        if resource_list != []:
            user_group_query = user_group_query.\
                filter(PolicyActionResourceModel.resource_id.in_(resource_list)).all()

        is_authorized = True
        if user_group_query:
            for row in user_group_query:
                is_authorized = is_authorized and row[0]
        else:
            is_authorized = is_implicit_allow

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
            query = session.query(PolicyUserGroupModel).filter_by(
                user_group_id=user_group_id).filter_by(policy_id=policy_id)
            if query.count() == 0:
                raise exception.NotFound(("Policy '%(policy_id)s' not attached to User/Group '%(user_group_id)s'") %
                                     {'user_group_id': user_group_id,
                                      'policy_id': policy_id})

            query = query.filter_by(type=type).delete()

    def _delete_user_group_policy_mapping(self, user_group_id,
                                       type=None):
        session = sql.get_session()
        with session.begin():
            session.query(PolicyUserGroupModel).filter_by(
                user_group_id=user_group_id).\
                filter_by(type=type).delete()

    def detach_user_policy(self, user_id):
        self._delete_user_group_policy_mapping(user_id,
                        type='UserPolicy')

    def detach_group_policy(self, group_id):
        self._delete_user_group_policy_mapping(group_id,
                        type='GroupPolicy')

    @sql.handle_conflicts(conflict_message='Policy is already attached to user')
    def attach_policy_to_user(self, policy_id, user_id):
        self._attach_policy_to_user_group(policy_id, user_id,
                                          type='UserPolicy')

    def detach_policy_from_user(self, policy_id, user_id):
        self._detach_policy_from_user_group(policy_id, user_id,
                                            type='UserPolicy')

    @sql.handle_conflicts(conflict_message='Policy is already attached to group')
    def attach_policy_to_group(self, policy_id, group_id):
        self._attach_policy_to_user_group(policy_id, group_id,
                                          type='GroupPolicy')

    def detach_policy_from_group(self, policy_id, group_id):
        self._detach_policy_from_user_group(policy_id, group_id,
                                            type='GroupPolicy')

    def attach_policy_to_resource(self, policy_id, account_id, resource):
        session = sql.get_session()
        with session.begin():
            resource_ids = [uuid.uuid4().hex for i in range(len(resource))]
            action_tuple = session.query(ActionModel).join(PolicyActionPrincipleModel)\
                          .filter(PolicyActionPrincipleModel.policy_id == policy_id)\
                          .with_entities(ActionModel.action_name).distinct().all()

            actions = [action[0] for action in action_tuple]
            try:
                zip_resource = zip(resource_ids, resource)
                self._get_policy(session, policy_id)

                for pair in itertools.product(actions, zip_resource):
                    #check if action is allowed in resource type

                    resource_type = Policy._get_resource_type(pair[1][1])
                    if resource_type is not None and resource_type is not '*' and self.is_action_resource_type_allowed(session, pair[0], resource_type) is False:
                        raise exception.ValidationError(
                                     attribute='valid resource type', target='resource')

                for pair in zip_resource:
                    resource = Policy._get_resource_list(pair[1])
                    res_acc_id = resource[3]
                    resource_service_name = resource[2]

                    if resource_service_name != 'dss':
                        raise exception.ValidationError(
                            attribute='valid service name', target='resource')

                    if res_acc_id != account_id:
                        raise exception.ValidationError(
                                     attribute='valid account id', target='resource')

                    session.add(ResourceModel(id=pair[0], name=pair[1],
                                    service_type=Policy._get_service_name(
                                        pair[1])))

                    session.add(PolicyResourceModel(policy_id=policy_id,
                                             resource_id=pair[0]))

            except sql.NotFound:
                raise exception.ValidationError(
                    attribute='valid action', target='policy')


    def detach_policy_from_resource(self, policy_id, resources):
        session = sql.get_session()
        self._get_policy(session, policy_id)

        for res in resources:
            resource = (session.query(ResourceModel.id).\
                filter(ResourceModel.name == res).all())
            resource_ids = [x[0] for x in resource]
            session.query(PolicyResourceModel)\
               .filter(PolicyResourceModel.resource_id.in_(resource_ids))\
               .filter(PolicyResourceModel.policy_id==policy_id)\
               .delete(synchronize_session='fetch')

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

    def get_policy_summary(self,policy_id):
        session = sql.get_session()
        policy = self._get_policy(session,policy_id)
        if policy.type != 'UserBased' or policy.hidden:
            raise exception.PolicyNotFound(policy_id=policy_id)

        query = session.query(PolicyUserGroupModel).filter_by(policy_id = policy_id) \
            .with_entities(
                    PolicyUserGroupModel.user_group_id, PolicyUserGroupModel.type)

        summary_list = {}
        summary_list['policy_document'] =policy.policy_blob
        summary_list['policy_jrn'] = 'jrn:jcs:iam:' + policy.account_id + ':Policy:' + policy.name
        summary_list['creation_time'] = policy.created_at
	
        sum_list = []
        for row in query:
            dict = {}
            dict['id'] = row.user_group_id
            dict['type'] = row.type
            sum_list.append(dict)

        summary_list['attached_entities'] = sum_list
        return summary_list

    def get_resource_based_policy_summary(self,policy_id):
        session = sql.get_session()
        policy = self._get_policy(session,policy_id)
        if policy.type != 'ResourceBased':
            raise exception.PolicyNotFound(policy_id=policy_id)

        query = session.query(PolicyResourceModel).join(ResourceModel)\
            .filter(PolicyResourceModel.policy_id == policy_id).with_entities(
                    ResourceModel.name)

        summary_list = {}
        summary_list['policy_document'] =policy.policy_blob
        summary_list['policy_jrn'] = 'jrn:jcs:iam:' + policy.account_id + ':Policy:' + policy.name
        summary_list['creation_time'] = policy.created_at

        sum_list = []
        for row in query:
            dict = {}
            resource = Policy._get_resource_list(row.name)
            dict['resource_id'] = resource[5]
            dict['resource_type'] = resource[4]
            sum_list.append(dict)

        summary_list['attached_entities'] = sum_list
        return summary_list

    def is_action_resource_type_allowed(self, session, action_name, resource_type):
        query = session.query(ActionModel).join(ActionResourceMappingModel).join(ResourceTypeModel)
        query = query.filter(ActionModel.action_name == action_name)
        rows = query.filter(ResourceTypeModel.name == resource_type).count()
        return True if rows > 0 else False

    @sql.handle_conflicts(conflict_message='Action already exists')
    def create_action(self, action_id, action_name, service_type):
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

    @sql.handle_conflicts(conflict_message='Resource type already exists')
    def create_resource_type(self, resource_type_id, resource_type_name, service_type):
        ref = dict()
        ref['id'] = resource_type_id
        ref['name'] = resource_type_name
        ref['service_type'] = service_type
        session = sql.get_session()
        with session.begin():
            try:
                session.add(ResourceTypeModel(id=resource_type_id, name=resource_type_name, service_type=service_type))
            except sql.DBReferenceError:
                raise exception.ValidationError(attribute='valid service name', target='resource')
        return ref

    @sql.handle_conflicts(conflict_message='Action resource type mapping already exists')
    def create_action_resource_type_mapping(self, action_name, resource_type_name, resource_type_service):
        ref = dict()
        ref['action_name'] = action_name
        ref['resource_type_name'] = resource_type_name
        session = sql.get_session()
        with session.begin():
            try:
                action_id = session.query(ActionModel).filter_by(
                                    action_name=action_name).with_entities(
                                            ActionModel.id).one()[0]
                query = session.query(ResourceTypeModel)
                query = query.filter_by(name=resource_type_name)
                query = query.filter_by(service_type=resource_type_service)
                resource_type = query.one()
                session.add(ActionResourceMappingModel(action_id=action_id, resource_type_id=resource_type.id))
            except sql.NotFound:
                raise exception.ValidationError(
                                attribute='valid action or valid resource name and service name',
                                target='ActionName, ResourceType or ResourceTypeSevice')
        return ref

    def get_policy_by_name(self, policy_name, account_id):
        session = sql.get_session()
        query = session.query(JioPolicyModel)
        query = query.filter_by(name=policy_name)
        query = query.filter_by(account_id=account_id)
        try:
            policy_ref = query.one()
        except sql.NotFound:
                raise exception.PolicyNameNotFound(policy_id=policy_name, account_id=account_id)
        return policy_ref

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

def create_resource_type(resource_type_id, resource_type_name, service_type):
    ref = dict()
    ref['id'] = resource_type_id
    ref['name'] = resource_type_name
    ref['service_type'] = service_type
    session = sql.get_session()
    with session.begin():
        try:
            session.add(ResourceTypeModel(id=resource_type_id, name=resource_type_name, service_type=service_type))
        except sql.DBReferenceError:
            raise exception.ValidationError(attribute='valid service name', target='resource')
    return ref

def create_action_resource_type_mapping(action_id, resource_type_id):
    ref = dict()
    ref['action_id'] = action_id
    ref['resource_type_id'] = resource_type_id
    session = sql.get_session()
    with session.begin():
        try:
            session.add(ActionResourceMappingModel(action_id=action_id, resource_type_id=resource_type_id))
        except sql.DBReferenceError:
            raise exception.ValidationError(attribute='valid action id or resource id', target='resource')
    return ref
