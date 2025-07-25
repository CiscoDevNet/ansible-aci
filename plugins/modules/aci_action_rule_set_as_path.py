#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_action_rule_set_as_path
short_description: Manage the AS Path action rules (rtctrl:SetASPath)
description:
- Set AS path action rule for the action rule profiles on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of the tenant.
    type: str
    aliases: [ tenant_name ]
  action_rule:
    description:
    - The name of the action rule profile.
    type: str
    aliases: [ action_rule_name ]
  last_as:
    description:
    - The last AS number value.
    type: int
    aliases: [ last_as_number ]
  criteria:
    description:
    - The option to append the specified AS number or to prepend the last AS numbers to the AS Path.
    type: str
    choices: [ prepend, prepend-last-as ]
  description:
    description:
    - The description for the action rule profile.
    type: str
    aliases: [ descr ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- The C(tenant) and the C(action_rule) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_tenant_action_rule_profile) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_tenant_action_rule_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(rtctrl:SetASPath).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Create a Set AS path action rule
  cisco.aci.aci_action_rule_set_as_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: prod
    last_as: 0
    criteria: prepend
    state: present
  delegate_to: localhost

- name: Query all Set AS path action rules
  cisco.aci.aci_action_rule_set_as_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a Set AS path action rule
  cisco.aci.aci_action_rule_set_as_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: prod
    criteria: prepend
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a Set AS path action rule
  cisco.aci.aci_action_rule_set_as_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: prod
    criteria: prepend
    state: absent
  delegate_to: localhost
"""

RETURN = r"""
current:
  description: The existing configuration from the APIC after the module has finished
  returned: success
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production environment",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
error:
  description: The error information as returned from the APIC
  returned: failure
  type: dict
  sample:
    {
        "code": "122",
        "text": "unknown managed object class foo"
    }
raw:
  description: The raw output returned by the APIC REST API (xml or json)
  returned: parse error
  type: str
  sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class foo"/></imdata>'
sent:
  description: The actual/minimal configuration pushed to the APIC
  returned: info
  type: list
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment"
            }
        }
    }
previous:
  description: The original configuration from the APIC before the module has started
  returned: info
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
proposed:
  description: The assembled configuration from the user-provided parameters
  returned: info
  type: dict
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment",
                "name": "production"
            }
        }
    }
filter_string:
  description: The filter string used for the request
  returned: failure or debug
  type: str
  sample: ?rsp-prop-include=config-only
method:
  description: The HTTP method used for the request to the APIC
  returned: failure or debug
  type: str
  sample: POST
response:
  description: The HTTP response from the APIC
  returned: failure or debug
  type: str
  sample: OK (30 bytes)
status:
  description: The HTTP status from the APIC
  returned: failure or debug
  type: int
  sample: 200
url:
  description: The HTTP url used for the request to the APIC
  returned: failure or debug
  type: str
  sample: https://10.11.12.13/api/mo/uni/tn-production.json
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        action_rule=dict(type="str", aliases=["action_rule_name"]),  # Not required for querying all objects
        last_as=dict(type="int", aliases=["last_as_number"]),
        criteria=dict(type="str", choices=["prepend", "prepend-last-as"]),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["action_rule", "tenant", "criteria"]],
            ["state", "present", ["action_rule", "tenant", "criteria"]],
        ],
    )

    last_as = module.params.get("last_as")
    criteria = module.params.get("criteria")
    description = module.params.get("description")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    action_rule = module.params.get("action_rule")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="rtctrlAttrP",
            aci_rn="attr-{0}".format(action_rule),
            module_object=action_rule,
            target_filter={"name": action_rule},
        ),
        subclass_2=dict(
            aci_class="rtctrlSetASPath",
            aci_rn="saspath-{0}".format(criteria),
            module_object=criteria,
            target_filter={"criteria": criteria},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="rtctrlSetASPath",
            class_config=dict(
                lastnum=last_as,
                criteria=criteria,
                descr=description,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="rtctrlSetASPath")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
