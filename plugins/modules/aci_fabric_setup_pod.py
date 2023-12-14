#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2023, Samita Bhattacharjee (@samitab) <samitab.cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from ansible_collections.cisco.aci.plugins.module_utils import constants

__metaclass__ = type

ANSIBLE_METADATA = constants.ANSIBLE_METADATA

DOCUMENTATION = r"""
---
module: aci_fabric_setup_pod
short_description: Manage Fabric Setup Pod (fabric:SetupP)
description:
- Manage Fabric Setup Policy of a Pod on Cisco ACI fabrics.
options:
  podId:
    description:
    - The Pod identifier.
    - Accepted value range between C(1) and C(254).
    type: int
    aliases: [ pod, id ]
  podType:
    description:
    - The Pod type
    type: str
    choices: [ physical, virtual ]
    default: physical
    aliases: [ type ]
  tepPool:
    description:
    - Infra TEP address pool
    - Must be valid IPv4 or IPv6
    type: str
    aliases: [ tep, pool ]
  description:
    description:
    - The description for the Fabric Setup Pod.
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
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fabric:SetupP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Samita Bhattacharjee (@samitab)
"""

EXAMPLES = r"""
- name: Add a fabric setup policy for a pod
  cisco.aci.aci_fabric_setup_pod:
    host: apic
    username: admin
    password: SomeSecretPassword
    podId: 1
    tepPool: 10.0.0.0/16
    state: present
  delegate_to: localhost

- name: Remove a fabric setup policy for a pod
  cisco.aci.aci_fabric_setup_pod:
    host: apic
    username: admin
    password: SomeSecretPassword
    podId: 1
    state: absent
  delegate_to: localhost

- name: Query the fabric setup policy for a pod
  cisco.aci.aci_fabric_setup_pod:
    host: apic
    username: admin
    password: SomeSecretPassword
    podId: 1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query fabric setup policy for all pods
  cisco.aci.aci_fabric_setup_pod:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result
"""

RETURN = constants.RETURN_DOC

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec

def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
        podId=dict(type="int", aliases=["pod", "id"]),
        podType=dict(type="str", default="physical", choices=["physical", "virtual" ], aliases=["type"]),
        tepPool=dict(type="str", aliases=["tep", "pool"])
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["podId"]],
            ["state", "present", ["podId"]],
        ],
    )

    aci = ACIModule(module)

    name_alias = module.params.get("name_alias")
    podId = module.params.get("podId")
    podType = module.params.get("podType")
    tepPool = module.params.get("tepPool")
    description = module.params.get("description")
    state = module.params.get("state")

    if podId is not None and int(podId) not in range(1, 254):
            aci.fail_json(msg="Pod ID: {0} is invalid; it must be in the range of 1 to 254.".format(podId))

    aci.construct_url(
        root_class=dict(
            aci_class="fabricSetupP",
            aci_rn="controller/setuppol/setupp-{0}".format(podId),
            module_object=podId,
            target_filter={"podId": podId},
        ),
        child_classes=["fabricExtRoutablePodSubnet","fabricExtSetupP"]
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fabricSetupP",
            class_config=dict(
                podId=podId,
                podType=podType,
                tepPool=tepPool,
                descr=description,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="fabricSetupP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()
