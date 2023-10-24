#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_action_rule_set_as_path_asn
short_description: Manage the AS Path ASN (rtctrl:SetASPathASN)
description:
- Set the ASN for the AS Path action rules on Cisco ACI fabrics.
- Only used if the AS Path action rule is set to C(prepend).
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
  asn:
    description:
    - The ASN number.
    type: int
  order:
    description:
    - The ASN order.
    type: int
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
- The C(tenant), the C(action_rule) and AS Path action rule used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_tenant_action_rule_profile) and M(cisco.aci.aci_action_rule_set_as_path) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_tenant_action_rule_profile
- module: cisco.aci.aci_action_rule_set_as_path
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(rtctrl:SetASPathASN).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Dag Wieers (@dagwieers)
"""

EXAMPLES = r"""
- name: Create a action rule profile
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: prod
    state: present
  delegate_to: localhost

- name: Delete a action rule profile
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: prod
    state: absent
  delegate_to: localhost

- name: Query all action rule profiles
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific action rule profile
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: prod
    state: query
  delegate_to: localhost
  register: query_result
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
        asn=dict(type="int"),
        order=dict(type="int"),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["action_rule", "tenant", "order"]],
            ["state", "present", ["action_rule", "tenant", "order"]],
        ],
    )

    asn = module.params.get("asn")
    order = module.params.get("order")
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
            aci_rn="saspath-prepend",
            module_object="prepend",
            target_filter={"criteria": "prepend"},
        ),
        subclass_3=dict(
            aci_class="rtctrlSetASPathASN",
            aci_rn="asn-{0}".format(order),
            module_object=order,
            target_filter={"asn": order},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="rtctrlSetASPathASN",
            class_config=dict(
                asn=asn,
                order=order,
                descr=description,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="rtctrlSetASPathASN")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
