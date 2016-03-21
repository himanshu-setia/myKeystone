# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystone.common.validation import parameter_types

_statement_schema = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "action": {
                "type": "array",
                "required": "true",
                "items": {
                    "type": "string",
                    "required": "true",
                    "minItems": 1
                }
            },
            "resource": {
                "type": "array",
                "required": "true",
                "items": {
                    "type": "string",
                    "required": "true",
                    "minItems": 1
                }
            },
            "effect": {
                "type": "string",
                "required": "true",
                "maxLength": 5
            }
        }
    }
}

_policy_properties = {
    "statement": _statement_schema,
    "name": parameter_types.name_string
}

policy_create = {
    "type": "object",
    "properties": _policy_properties,
    "required": ["statement", "name"],
}

policy_update = {
    "type": "object",
    "properties": _policy_properties,
}
