#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Jacob McGill (jmcgill298)
# Copyright: (c) 2018, Dag Wieers (dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_vlan_pool_encap_block
short_description: Manage encap blocks assigned to VLAN pools (fvns:EncapBlk)
description:
- Manage VLAN encap blocks that are assigned to VLAN pools on Cisco ACI fabrics.
options:
  allocation_mode:
    description:
    - The method used for allocating encaps to resources.
    type: str
    choices: [ dynamic, inherit, static]
    aliases: [ mode ]
  description:
    description:
    - Description for the pool encap block.
    type: str
    aliases: [ descr ]
  pool:
    description:
    - The name of the pool that the encap block should be assigned to.
    type: str
    aliases: [ pool_name ]
  pool_allocation_mode:
    description:
    - The method used for allocating encaps to resources.
    type: str
    choices: [ dynamic, static]
    aliases: [ pool_mode ]
  block_end:
    description:
    - The end of encap block.
    type: int
    aliases: [ end ]
  block_name:
    description:
    - The name to give to the encap block.
    type: str
    aliases: [ name ]
  block_start:
    description:
    - The start of the encap block.
    type: int
    aliases: [ start ]
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
- The C(pool) must exist in order to add or delete a encap block.
seealso:
- module: cisco.aci.aci_encap_pool_range
- module: cisco.aci.aci_vlan_pool
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fvns:EncapBlk).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Jacob McGill (@jmcgill298)
- Dag Wieers (@dagwieers)
"""

EXAMPLES = r"""
- name: Add a new VLAN encap block
  cisco.aci.aci_vlan_pool_encap_block:
    host: apic
    username: admin
    password: SomeSecretPassword
    pool: production
    pool_allocation_mode: static
    block_start: 20
    block_end: 50
    state: present
  delegate_to: localhost

- name: Remove a VLAN encap block
  cisco.aci.aci_vlan_pool_encap_block:
    host: apic
    username: admin
    password: SomeSecretPassword
    pool: production
    pool_allocation_mode: static
    block_start: 20
    block_end: 50
    state: absent
  delegate_to: localhost

- name: Query a VLAN encap block
  cisco.aci.aci_vlan_pool_encap_block:
    host: apic
    username: admin
    password: SomeSecretPassword
    pool: production
    pool_allocation_mode: static
    block_start: 20
    block_end: 50
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a VLAN pool for encap blocks
  cisco.aci.aci_vlan_pool_encap_block:
    host: apic
    username: admin
    password: SomeSecretPassword
    pool: production
    pool_allocation_mode: static
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all VLAN encap blocks
  cisco.aci.aci_vlan_pool_encap_block:
    host: apic
    username: admin
    password: SomeSecretPassword
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
        pool=dict(type="str", aliases=["pool_name"]),  # Not required for querying all objects
        block_name=dict(type="str", aliases=["name"]),  # Not required for querying all objects
        block_end=dict(type="int", aliases=["end"]),  # Not required for querying all objects
        block_start=dict(type="int", aliases=["start"]),  # Not required for querying all objects
        allocation_mode=dict(type="str", aliases=["mode"], choices=["dynamic", "inherit", "static"]),
        description=dict(type="str", aliases=["descr"]),
        pool_allocation_mode=dict(type="str", aliases=["pool_mode"], choices=["dynamic", "static"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['pool', 'pool_allocation_mode', 'block_end', 'block_start']],
            ['state', 'present', ['pool', 'pool_allocation_mode', 'block_end', 'block_start']],
        ],
    )

    allocation_mode = module.params.get("allocation_mode")
    description = module.params.get("description")
    pool = module.params.get("pool")
    pool_allocation_mode = module.params.get("pool_allocation_mode")
    block_end = module.params.get("block_end")
    block_name = module.params.get("block_name")
    block_start = module.params.get("block_start")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    if block_end is not None:
        encap_end = "vlan-{0}".format(block_end)
    else:
        encap_end = None

    if block_start is not None:
        encap_start = "vlan-{0}".format(block_start)
    else:
        encap_start = None

    # Collect proper mo information
    aci_block_mo = "from-[{0}]-to-[{1}]".format(encap_start, encap_end)
    pool_name = pool

    # Validate block_end and block_start are valid for its respective encap type
    for encap_id in block_end, block_start:
        if encap_id is not None:
            if not 1 <= encap_id <= 4094:
                module.fail_json(msg="vlan pools must have 'block_start' and 'block_end' values between 1 and 4094")

    if block_end is not None and block_start is not None:
        # Validate block_start is less than block_end
        if block_start > block_end:
            module.fail_json(msg="The 'block_start' must be less than or equal to the 'block_end'")

    elif block_end is None and block_start is None:
        if block_name is None:
            # Reset range managed object to None for aci util to properly handle query
            aci_block_mo = None

    # ACI Pool URL requires the allocation mode (ex: uni/infra/vlanns-[poolname]-static)
    if pool is not None:
        if pool_allocation_mode is not None:
            pool_name = "[{0}]-{1}".format(pool, pool_allocation_mode)
        else:
            module.fail_json(msg="ACI requires the 'pool_allocation_mode' when 'pool' is provided")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvnsVlanInstP",
            aci_rn="infra/vlanns-{0}".format(pool_name),
            module_object=pool,
            target_filter={"name": pool},
        ),
        subclass_1=dict(
            aci_class="fvnsEncapBlk",
            aci_rn=aci_block_mo,
            module_object=aci_block_mo,
            target_filter={"from": encap_start, "to": encap_end, "name": block_name},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fvnsEncapBlk",
            class_config={
                "allocMode": allocation_mode,
                "descr": description,
                "from": encap_start,
                "name": block_name,
                "to": encap_end,
                "nameAlias": name_alias,
            },
        )

        aci.get_diff(aci_class="fvnsEncapBlk")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
