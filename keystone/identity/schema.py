from keystone.common import validation
from keystone.common.validation import parameter_types

_user_properties = {
    "name": parameter_types.name_string,
    "account_id" : parameter_types.id_string,
    "description": validation.nullable(parameter_types.description),
    "enabled" : parameter_types.boolean
}

user_create = {
    'type': 'object',
    'properties': _user_properties,
    'required': ['name'],
    'additionalProperties': True
}

user_update = {
    'type': 'object',
    'properties': _user_properties,
    'minProperties': 1,
    'additionalProperties': True
}

_group_properties = {
    "name": parameter_types.name_string,
    "account_id" : parameter_types.id_string,
    "description": validation.nullable(parameter_types.description),
}

group_create = {
    'type': 'object',
    'properties': _group_properties,
    'required': ['name'],
    'additionalProperties': True
}

group_update = {
    'type': 'object',
    'properties': _group_properties,
    'minProperties': 1,
    'additionalProperties': True
}
