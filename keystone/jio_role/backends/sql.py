@dependency.requires('identity_api','resource_api')
class Role(jio_role.Driver):

    @sql.handle_conflicts(conflict_message='Role name already exist')
    def create_role(self, account_id, role_id, role):
        ref = copy.deepcopy(role)
        ref['id'] = role_id
        name = role.get('name', None)
        statement = role.get('statement', None)
        created_at = datetime.utcnow()

        with sql.transaction() as session:
            session.add(JioRoleModel(id=role_id, name=name,
                        account_id=account_id,
                        created_at=created_at,
                        updated_at=created_at,
                        trust_policy_blob=jsonutils.dumps(ref)))
            for stmt in statement:
                action = stmt.get('action', None)
                effect = stmt.get('effect', None)
                principal = stmt.get('principal', None)

                # Autofill account id in principal
                for index, item in enumerate(principal):
                    if len(item.split(':')) > 4 and item.split(':')[3]=='':
                        var=item.split(':')
                        var[3]=account_id
                        principal[index]=':'.join(var)

                if effect == 'allow':
                    effect = True
                elif effect == 'deny':
                    effect = False
                else:
                    raise exception.ValidationError(attribute='allow or deny',
                                                    target='effect')
                # TODO(himanshu): Check if the action name is valid
                # TODO(himanshu): Check if the principal name is valid

                session.add(TrustPolicyStatementModel(id=uuid.uuid4().hex ,
                                                      jio_role_id=role_id,
                                                      effect=effect,
                                                      principal_jrn=principal,
                                                      action=action,
                                                      type='user'))

        return ref

    def _get_role(self, session, role_id):
        """Private method to get a role model object (NOT a dictionary)."""
        ref = session.query(JioRoleModel).get(role_id)
        if not ref:
            raise exception.RoleNotFound(role_id=role_id)
        return ref

    def delete_role(self, role_id):
        session = sql.get_session()

        with session.begin():
            role_ref = self._get_role(session, policy_id)
            # Clear JioRolePolicyMapping
            session.query(JioRolePolicyModel).filter_by(
                role_id=role_ref.id).delete()
            jio_role_user_ref = session.query(JioRoleUserModel).filter_by(
                jio_role_id=role_ref.id)
            # Clear JioRoleCredentials
            session.query(JioRoleCredentialsModel).filter_by(
                jio_role_user_id=jio_role_user_ref.id).delete()
            # Clear JioRoleTokens
            session.query(JioRoleTokensModel).filter_by(
                jio_role_user_id=jio_role_user_ref.id).delete()
            # Clear JioRoleUser
            session.query(JioRoleUserModel).filter_by(
                jio_role_id=role_ref.id).delete()
            # Clear TrustPolicyStatement
            session.query(TrustPolicyStatementModel).filter_by(
                jio_role_id=role_ref.id).delete()
            # Clear JioRole
            session.query(JioRoleModel).filter_by(
                id=role_ref.id).delete()

    def list_roles(self, account_id):
        session = sql.get_session()
        refs = session.query(JioRoleModel).filter_by(account_id=account_id).\
                    with_entities(JioRoleModel.id, JioRoleModel.name,
                                  JioRoleModel.created_at)
        ret = []
        attrs_to_return = ['id', 'name', 'created_at']
        for ref in refs:
            for index, value in enumerate(ref)
                new_ref[attrs_to_return[index]] = value
            ret.append(new_ref)
        return ret

    def update_role(self, account_id, role_id, role):
        session = sql.get_session()

        with session.begin():
            ref = self._get_role(session, role_id)
            ref.id = role_id
            ref.name = role.get('name')
            ref.trust_policy_blob = role.get('trust_policy_blob')
            ref.updated_at = datetime.utcnow()
            # Clear existing trust_policy_statement related to this role
            session.query(TrustPolicyStatementModel).filter_by(
                             jio_role_id=role_id).delete()
            # Add new trust_policy_statement
            if 'trust_policy_blob' in role:
                trust_policy_blob = role.get('trust_policy_blob')
                trust_policy_blob['statement'] = copy.deepcopy(statement)
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

                    # TODO(himanshu): Check if the action name is valid
                    # TODO(himanshu): Check if the principal name is valid
                    session.add(TrustPolicyStatementModel(id=uuid.uuid4().hex ,
                                                          jio_role_id=role_id,
                                                          effect=effect,
                                                          principal_jrn=principal,
                                                          action=action,
                                                          type='user'))

        return ref

    def get_role_summary(self, role_id):
        session = sql.get_session()
        role = self._get_role(session, role_id)
        role_ref = session.query(JioRoleModel).filter_by(id=role_id).\
                    with_entities(JioRoleModel.id, JioRoleModel.name,
                                  JioRoleModel.trust_policy_blob,
                                  JioRoleModel.created_at, JioRoleModel.updated_at)
        summary_list = {}
        summary_list['role_id'] = role.id
        summary_list['role_name'] = role.name
        summary_list['trust_policy'] = role.trust_policy_blob
        summary_list['role_jrn'] = 'jrn:jcs:iam:'+role.account_id+':Role:'+role.name
        summary_list['created_at'] = role.created_at
        summary_list['last_updated_at'] = role.updated_at

        role_policy_ref = session.query(JioRolePolicyModel).filter_by(jio_role_id=role_id)
        summary_list['policy_count_attached_to_role'] = role_policy_ref.count()

        role_user_ref = session.query(JioRoleUserModel).filter_by(jio_role_id=role_id)
        summary_list['user_count_attached_to_role'] = role_user_ref.count()

        #TODO(himanshu):
        #summary_list['policies_attached_to_role']
        #summary_list['users_attached_to_role']
        return summary_list

    def get_role(self, role_id):
        session = sql.get_session()
        role = self._get_role(session, role_id)
        return role


