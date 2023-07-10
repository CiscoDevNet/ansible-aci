#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Sabari Jaganathan <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_interface_policy_group
short_description: Manage Fabric Interface Policy Groups (fabric:LePortPGrp, fabric:SpPortPGrp)
description:
- Manage Fabric Interface Policy Groups on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the Fabric Leaf or Spine Interface Policy Group.
    type: str
    aliases: [ policy_group ]
  description:
    description:
    - The description of the Fabric Leaf or Spine Interface Policy Group.
    type: str
    aliases: [ descr ]
  type:
    description:
    - The type of the Fabric Leaf or Spine Interface Policy Group.
    - Use C(leaf) to create a Fabric Leaf Interface Policy Group.
    - Use C(spine) to create a Fabric Spine Interface Policy Group.
    type: str
    aliases: [ policy_group_type ]
    choices: [ leaf, spine ]
    required: true
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
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fabric:LePortPGrp, fabric:SpPortPGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sabari Jaganathan (@sajagana)
"""

EXAMPLES = r"""
- name: Add a Fabric Leaf Policy Group
  cisco.aci.aci_fabric_interface_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: leaf_policy_group
    type: leaf
    state: present
  delegate_to: localhost

- name: Query a Fabric Leaf Policy Group with name
  cisco.aci.aci_fabric_interface_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: leaf_policy_group
    type: leaf
    state: query
  delegate_to: localhost

- name: Query all Fabric Leaf Policy Groups
  cisco.aci.aci_fabric_interface_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    type: leaf
    state: query
  delegate_to: localhost

- name: Remove a Fabric Leaf Policy Group
  cisco.aci.aci_fabric_interface_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: leaf_policy_group
    type: leaf
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["policy_group"]),
        description=dict(type="str", aliases=["descr"]),
        name_alias=dict(type="str"),
        type=dict(type="str", aliases=["policy_group_type"], choices=["leaf", "spine"], required=True),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
    )

    aci = ACIModule(module)

    name = module.params.get("name")
    description = module.params.get("description")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")
    policy_group_type = module.params.get("type")

    if policy_group_type == "leaf":
        policy_group_class_name = "fabricLePortPGrp"
        policy_group_class_rn = "leportgrp-{0}".format(name)
    else:
        policy_group_class_name = "fabricSpPortPGrp"
        policy_group_class_rn = "spportgrp-{0}".format(name)

    aci.construct_url(
        root_class=dict(
            aci_class="fabric",
            aci_rn="fabric",
        ),
        subclass_1=dict(
            aci_class="fabricFuncP",
            aci_rn="funcprof",
            module_object=None,
            target_filter=None,
        ),
        subclass_2=dict(
            aci_class=policy_group_class_name,
            aci_rn=policy_group_class_rn,
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=[
            "fabricRsDwdmFabIfPol",
            "fabricRsFIfPol",
            "fabricRsFLinkFlapPol",
            "fabricRsL3IfPol",
            "fabricRsMacsecFabIfPol",
            "fabricRsMonIfFabricPol",
        ],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=policy_group_class_name,
            class_config=dict(
                name=name,
                descr=description,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class=policy_group_class_name)

        aci.post_config()

    if state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
