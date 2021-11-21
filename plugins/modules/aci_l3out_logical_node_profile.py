#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l3out_logical_node_profile
short_description: Manage Layer 3 Outside (L3Out) logical node profiles (l3extLNodeP:lnodep)
description:
- Manage Layer 3 Outside (L3Out) logical node profiles on Cisco ACI fabrics.
options:
  node_profile:
    description:
    - Name of the node profile.
    type: str
    aliases: [ node_profile_name, name, logical_node ]
  description:
    description:
    - Description for the node profile.
    type: str
    aliases: [ descr ]
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l3out:
    description:
    - Name of an existing L3Out.
    type: str
    aliases: [ l3out_name ]
  dscp:
    description:
    - The target Differentiated Service (DSCP) value.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43, CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, unspecified ]
    aliases: [ target_dscp ]
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
- cisco.aci.owner

seealso:
- module: aci_l3out
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(vmm:DomP)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Jason Juenger (@jasonjuenger)
"""

EXAMPLES = r"""
- name: Add a new node profile
  cisco.aci.aci_l3out_logical_node_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    node_profile: my_node_profile
    description: node profile for my_l3out
    l3out: my_l3out
    tenant: my_tenant
    dscp: CS0
    state: present
  delegate_to: localhost

- name: Delete a node profile
  cisco.aci.aci_l3out_logical_node_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    node_profile: my_node_profile
    l3out: my_l3out
    tenant: my_tenant
    state: absent
  delegate_to: localhost

- name: Query a node profile
  cisco.aci.aci_l3out_logical_node_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    node_profile: my_node_profile
    l3out: my_l3out
    tenant: my_tenant
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all node profile for L3out
  cisco.aci.aci_l3out_logical_node_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    l3out: my_l3out
    tenant: my_tenant
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        node_profile=dict(type="str", aliases=["name", "node_profile_name", "logical_node"]),
        tenant=dict(type="str", aliases=["tenant_name"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        description=dict(type="str", aliases=["descr"]),
        dscp=dict(
            type="str",
            choices=[
                "AF11",
                "AF12",
                "AF13",
                "AF21",
                "AF22",
                "AF23",
                "AF31",
                "AF32",
                "AF33",
                "AF41",
                "AF42",
                "AF43",
                "CS0",
                "CS1",
                "CS2",
                "CS3",
                "CS4",
                "CS5",
                "CS6",
                "CS7",
                "EF",
                "VA",
                "unspecified",
            ],
            aliases=["target_dscp"],
        ),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "l3out", "node_profile"]],
            ["state", "present", ["tenant", "l3out", "node_profile"]],
        ],
    )

    node_profile = module.params.get("node_profile")
    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    description = module.params.get("description")
    dscp = module.params.get("dscp")
    state = module.params.get("state")
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
            aci_class="l3extOut",
            aci_rn="out-{0}".format(l3out),
            module_object=l3out,
            target_filter={"name": l3out},
        ),
        subclass_2=dict(
            aci_class="l3extLNodeP",
            aci_rn="lnodep-{0}".format(node_profile),
            module_object=node_profile,
            target_filter={"name": node_profile},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="l3extLNodeP",
            class_config=dict(
                descr=description,
                name=node_profile,
                targetDscp=dscp,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="l3extLNodeP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
