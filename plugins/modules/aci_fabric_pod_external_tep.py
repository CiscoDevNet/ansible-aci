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
module: aci_fabric_pod_external_tep
short_description: Manage Fabric Pod External TEP (fabric:ExtRoutablePodSubnet)
description:
- Manage External TEP Fabric Pod Subnets.
options:
  podId:
    description:
    - The Pod ID for the External TEP.
    type: int
    aliases: [ pod ]
  description:
    description:
    - The description for the External TEP.
    type: str
    aliases: [ descr ]
  nameAlias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
  pool:
    description:
    - The subnet IP address pool
    type: str
    aliases: [ ip, ipAddress, tepPool ]
  reserveAddressCount:
    description:
    - Indicates the number of IP addresses that are reserved from the start of the subnet.
    type: int
    aliases: [ addressCount ]
  status:
    description:
    - State of the External TEP C(active) or C(inactive)
    - An External TEP can only be deleted when the state is inactive.
    type: str
    choices: [ active, inactive ]
    default: active
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

notes:
- The C(Fabric Setup Pod Policy) must exist before using this module in your playbook.
  The M(cisco.aci.aci_fabric_setup_pod) can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fabric:ExtRoutablePodSubnet).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Samita Bhattacharjee (@samitab)
"""

EXAMPLES = r"""
- name: Add an External TEP to a pod fabic setup policy
  cisco.aci.aci_fabric_pod_external_tep:
    host: apic
    username: admin
    password: SomeSecretPassword
    podId: 2
    pool: 10.6.1.0/24
    addressCount: 5
    status: active
    state: present
  delegate_to: localhost

- name: Change an External TEP state on a pod fabic setup policy to inactive
  cisco.aci.aci_fabric_pod_external_tep:
    host: apic
    username: admin
    password: SomeSecretPassword
    podId: 2
    pool: 10.6.1.0/24
    status: inactive
    state: present
  delegate_to: localhost

- name: Delete an External TEP on a pod fabic setup policy
  cisco.aci.aci_fabric_pod_external_tep:
    host: apic
    username: admin
    password: SomeSecretPassword
    podId: 2
    pool: 10.6.1.0/24
    state: absent
  delegate_to: localhost

- name: Query the External TEP on a pod fabic setup policy
  cisco.aci.aci_fabric_pod_external_tep:
    host: apic
    username: admin
    password: SomeSecretPassword
    podId: 2
    pool: 10.6.1.0/24
    state: query
  delegate_to: localhost
  register: query_result

- name: Query External TEPs on all pod fabic setup policies
  cisco.aci.aci_fabric_pod_external_tep:
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
        description=dict(type=str, aliases=["descr"]),
        nameAlias=dict(type=str),
        podId=dict(type=int, aliases=["pod"]),
        pool=dict(type=str, aliases=["ip", "ipAddress", "tepPool"]),
        reserveAddressCount=dict(type=int, aliases=["addressCount"]),
        status=dict(type=str, default="active", choices=["active", "inactive"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["podId", "pool"]],
            ["state", "present", ["podId", "pool"]],
        ],
    )

    aci = ACIModule(module)

    podId = module.params.get("podId")
    descr = module.params.get("descr")
    nameAlias = module.params.get("nameAlias")
    pool = module.params.get("pool")
    reserveAddressCount = module.params.get("reserveAddressCount")
    status = module.params.get("status")
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
        subclass_1=dict(
            aci_class="fabricExtRoutablePodSubnet",
            aci_rn="extrtpodsubnet-[{0}]".format(pool),
            module_object=pool,
            target_filter={"pool": pool}
        )
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fabricExtRoutablePodSubnet",
            class_config=dict(
                descr=descr,
                nameAlias=nameAlias,
                pool=pool,
                reserveAddressCount=reserveAddressCount,
                state=status,
            ),
        )

        aci.get_diff(aci_class="fabricExtRoutablePodSubnet")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()