#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_encap_pool_range
short_description: Manage encap ranges assigned to pools (fvns:EncapBlk, fvns:VsanEncapBlk)
description:
- Manage vlan, vxlan, and vsan ranges that are assigned to pools on Cisco ACI fabrics.
options:
  allocation_mode:
    description:
    - The method used for allocating encaps to resources.
    - Only vlan and vsan support allocation modes.
    type: str
    choices: [ dynamic, inherit, static]
    aliases: [ mode ]
  description:
    description:
    - Description for the pool range.
    type: str
    aliases: [ descr ]
  pool:
    description:
    - The name of the pool that the range should be assigned to.
    type: str
    aliases: [ pool_name ]
  pool_allocation_mode:
    description:
    - The method used for allocating encaps to resources.
    - Only vlan and vsan support allocation modes.
    type: str
    choices: [ dynamic, static]
    aliases: [ pool_mode ]
  pool_type:
    description:
    - The encap type of C(pool).
    type: str
    required: yes
    aliases: [ type ]
    choices: [ vlan, vxlan, vsan]
  range_end:
    description:
    - The end of encap range.
    type: int
    aliases: [ end ]
  range_name:
    description:
    - The name to give to the encap range.
    type: str
    aliases: [ name, range ]
  range_start:
    description:
    - The start of the encap range.
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
- The C(pool) must exist in order to add or delete a range.
seealso:
- module: cisco.aci.aci_encap_pool
- module: cisco.aci.aci_vlan_pool_encap_block
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(fvns:EncapBlk) and B(fvns:VsanEncapBlk).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Jacob McGill (@jmcgill298)
"""

EXAMPLES = r"""
- name: Add a new VLAN pool range
  cisco.aci.aci_encap_pool_range:
    host: apic
    username: admin
    password: SomeSecretPassword
    pool: production
    pool_type: vlan
    pool_allocation_mode: static
    range_name: anstest
    range_start: 20
    range_end: 40
    allocation_mode: inherit
    state: present
  delegate_to: localhost

- name: Remove a VLAN pool range
  cisco.aci.aci_encap_pool_range:
    host: apic
    username: admin
    password: SomeSecretPassword
    pool: production
    pool_type: vlan
    pool_allocation_mode: static
    range_name: anstest
    range_start: 20
    range_end: 40
    state: absent
  delegate_to: localhost

- name: Query a VLAN range
  cisco.aci.aci_encap_pool_range:
    host: apic
    username: admin
    password: SomeSecretPassword
    pool: production
    pool_type: vlan
    pool_allocation_mode: static
    range_name: anstest
    range_start: 20
    range_end: 50
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a VLAN pool for ranges by range_name
  cisco.aci.aci_encap_pool_range:
    host: apic
    username: admin
    password: SomeSecretPassword
    pool_type: vlan
    range_name: anstest
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a VLAN pool for ranges by range_start
  cisco.aci.aci_encap_pool_range:
    host: apic
    username: admin
    password: SomeSecretPassword
    pool_type: vlan
    range_start: 20
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a VLAN pool for ranges by range_start and range_end
  cisco.aci.aci_encap_pool_range:
    host: apic
    username: admin
    password: SomeSecretPassword
    pool_type: vlan
    range_start: 20
    range_end: 40
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all VLAN pool ranges
  cisco.aci.aci_encap_pool_range:
    host: apic
    username: admin
    password: SomeSecretPassword
    pool_type: vlan
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

ACI_POOL_MAPPING = dict(
    vlan=dict(
        aci_class="fvnsVlanInstP",
        aci_mo="infra/vlanns-",
    ),
    vxlan=dict(
        aci_class="fvnsVxlanInstP",
        aci_mo="infra/vxlanns-",
    ),
    vsan=dict(
        aci_class="fvnsVsanInstP",
        aci_mo="infra/vsanns-",
    ),
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        pool_type=dict(type="str", required=True, aliases=["type"], choices=["vlan", "vxlan", "vsan"]),
        allocation_mode=dict(type="str", aliases=["mode"], choices=["dynamic", "inherit", "static"]),
        description=dict(type="str", aliases=["descr"]),
        pool=dict(type="str", aliases=["pool_name"]),  # Not required for querying all objects
        pool_allocation_mode=dict(type="str", aliases=["pool_mode"], choices=["dynamic", "static"]),
        range_end=dict(type="int", aliases=["end"]),  # Not required for querying all objects
        range_name=dict(type="str", aliases=["name", "range"]),  # Not required for querying all objects
        range_start=dict(type="int", aliases=["start"]),  # Not required for querying all objects
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["pool", "range_end", "range_name", "range_start"]],
            ["state", "present", ["pool", "range_end", "range_name", "range_start"]],
        ],
    )

    allocation_mode = module.params.get("allocation_mode")
    description = module.params.get("description")
    pool = module.params.get("pool")
    pool_allocation_mode = module.params.get("pool_allocation_mode")
    pool_type = module.params.get("pool_type")
    range_end = module.params.get("range_end")
    range_name = module.params.get("range_name")
    range_start = module.params.get("range_start")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    if range_end is not None:
        encap_end = "{0}-{1}".format(pool_type, range_end)
    else:
        encap_end = None

    if range_start is not None:
        encap_start = "{0}-{1}".format(pool_type, range_start)
    else:
        encap_start = None

    ACI_RANGE_MAPPING = dict(
        vlan=dict(
            aci_class="fvnsEncapBlk",
            aci_mo="from-[{0}]-to-[{1}]".format(encap_start, encap_end),
        ),
        vxlan=dict(
            aci_class="fvnsEncapBlk",
            aci_mo="from-[{0}]-to-[{1}]".format(encap_start, encap_end),
        ),
        vsan=dict(
            aci_class="fvnsVsanEncapBlk",
            aci_mo="vsanfrom-[{0}]-to-[{1}]".format(encap_start, encap_end),
        ),
    )

    # Collect proper class and mo information based on pool_type
    aci_range_class = ACI_RANGE_MAPPING[pool_type]["aci_class"]
    aci_range_mo = ACI_RANGE_MAPPING[pool_type]["aci_mo"]
    aci_pool_class = ACI_POOL_MAPPING[pool_type]["aci_class"]
    aci_pool_mo = ACI_POOL_MAPPING[pool_type]["aci_mo"]
    pool_name = pool

    # Validate range_end and range_start are valid for its respective encap type
    for encap_id in range_end, range_start:
        if encap_id is not None:
            if pool_type == "vlan":
                if not 1 <= encap_id <= 4094:
                    module.fail_json(msg='vlan pools must have "range_start" and "range_end" values between 1 and 4094')
            elif pool_type == "vxlan":
                if not 5000 <= encap_id <= 16777215:
                    module.fail_json(msg='vxlan pools must have "range_start" and "range_end" values between 5000 and 16777215')
            elif pool_type == "vsan":
                if not 1 <= encap_id <= 4093:
                    module.fail_json(msg='vsan pools must have "range_start" and "range_end" values between 1 and 4093')

    if range_end is not None and range_start is not None:
        # Validate range_start is less than range_end
        if range_start > range_end:
            module.fail_json(msg='The "range_start" must be less than or equal to the "range_end"')

    elif range_end is None and range_start is None:
        if range_name is None:
            # Reset range managed object to None for aci util to properly handle query
            aci_range_mo = None

    # Vxlan does not support setting the allocation mode
    if pool_type == "vxlan" and allocation_mode is not None:
        module.fail_json(msg='vxlan pools do not support setting the "allocation_mode"; please omit this parameter for vxlan pools')

    # ACI Pool URL requires the allocation mode for vlan and vsan pools (ex: uni/infra/vlanns-[poolname]-static)
    if pool_type != "vxlan" and pool is not None:
        if pool_allocation_mode is not None:
            pool_name = "[{0}]-{1}".format(pool, pool_allocation_mode)
        else:
            module.fail_json(msg='ACI requires the "pool_allocation_mode" for "pool_type" of "vlan" and "vsan" when the "pool" is provided')

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class=aci_pool_class,
            aci_rn="{0}{1}".format(aci_pool_mo, pool_name),
            module_object=pool,
            target_filter={"name": pool},
        ),
        subclass_1=dict(
            aci_class=aci_range_class,
            aci_rn="{0}".format(aci_range_mo),
            module_object=aci_range_mo,
            target_filter={"from": encap_start, "to": encap_end, "name": range_name},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=aci_range_class,
            class_config={
                "allocMode": allocation_mode,
                "descr": description,
                "from": encap_start,
                "name": range_name,
                "to": encap_end,
                "nameAlias": name_alias,
            },
        )

        aci.get_diff(aci_class=aci_range_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
