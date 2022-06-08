#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Simon Metzger <smnmtzgr@gmail.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_access_sub_port_block_to_access_port
short_description: Manage sub port blocks of Fabric interface policy leaf profile interface selectors (infra:HPortS, infra:SubPortBlk)
description:
- Manage sub port blocks of Fabric interface policy leaf profile interface selectors on Cisco ACI fabrics.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(infra:HPortS) and B(infra:SubPortBlk).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Simon Metzger (@smnmtzgr)
options:
  leaf_interface_profile:
    description:
    - The name of the Fabric access policy leaf interface profile.
    type: str
    aliases: [ leaf_interface_profile_name ]
  access_port_selector:
    description:
    -  The name of the Fabric access policy leaf interface profile access port selector.
    type: str
    aliases: [ name, access_port_selector_name ]
  leaf_port_blk:
    description:
    - The name of the Fabric access policy leaf interface profile access port block.
    type: str
    aliases: [ leaf_port_blk_name ]
  leaf_port_blk_description:
    description:
    - The description to assign to the C(leaf_port_blk).
    type: str
  from_port:
    description:
    - The beginning (from-range) of the port range block for the leaf access port block.
    type: str
    aliases: [ from, fromPort, from_port_range ]
  to_port:
    description:
    - The end (to-range) of the port range block for the leaf access port block.
    type: str
    aliases: [ to, toPort, to_port_range ]
  from_sub_port:
    description:
    - The beginning (from-range) of the sub port range block for the leaf access port block.
    type: str
    aliases: [ fromSubPort, from_sub_port_range ]
  to_sub_port:
    description:
    - The end (to-range) of the sub port range block for the leaf access port block.
    type: str
    aliases: [ toSubPort, to_sub_port_range ]
  from_card:
    description:
    - The beginning (from-range) of the card range block for the leaf access port block.
    type: str
    aliases: [ from_card_range ]
  to_card:
    description:
    - The end (to-range) of the card range block for the leaf access port block.
    type: str
    aliases: [ to_card_range ]
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

"""

EXAMPLES = r"""
- name: Associate an access sub port block (single port) to an interface selector
  cisco.aci.aci_access_sub_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    leaf_interface_profile: leafintprfname
    access_port_selector: accessportselectorname
    leaf_port_blk: leafportblkname
    from_port: 13
    to_port: 13
    from_sub_port: 1
    to_sub_port: 1
    state: present
  delegate_to: localhost

- name: Associate an access sub port block (port range) to an interface selector
  cisco.aci.aci_access_sub_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    leaf_interface_profile: leafintprfname
    access_port_selector: accessportselectorname
    leaf_port_blk: leafportblkname
    from_port: 13
    to_port: 13
    from_sub_port: 1
    to_sub_port: 3
    state: present
  delegate_to: localhost

- name: Remove an access sub port block from an interface selector
  cisco.aci.aci_access_sub_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    leaf_interface_profile: leafintprfname
    access_port_selector: accessportselectorname
    leaf_port_blk: leafportblkname
    from_port: 13
    to_port: 13
    from_sub_port: 1
    to_sub_port: 1
    state: absent
  delegate_to: localhost

- name: Query Specific access sub port block under given access port selector
  cisco.aci.aci_access_sub_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    leaf_interface_profile: leafintprfname
    access_port_selector: accessportselectorname
    leaf_port_blk: leafportblkname
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all access sub port blocks under given leaf interface profile
  cisco.aci.aci_access_sub_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    leaf_interface_profile: leafintprfname
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all access sub port blocks in the fabric
  cisco.aci.aci_access_sub_port_block_to_access_port:
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

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        leaf_interface_profile=dict(type="str", aliases=["leaf_interface_profile_name"]),  # Not required for querying all objects
        access_port_selector=dict(type="str", aliases=["name", "access_port_selector_name"]),  # Not required for querying all objects
        leaf_port_blk=dict(type="str", aliases=["leaf_port_blk_name"]),  # Not required for querying all objects
        leaf_port_blk_description=dict(type="str"),
        from_port=dict(type="str", aliases=["from", "fromPort", "from_port_range"]),  # Not required for querying all objects and deleting sub port blocks
        to_port=dict(type="str", aliases=["to", "toPort", "to_port_range"]),  # Not required for querying all objects and deleting sub port blocks
        from_sub_port=dict(type="str", aliases=["fromSubPort", "from_sub_port_range"]),  # Not required for querying all objects and deleting sub port blocks
        to_sub_port=dict(type="str", aliases=["toSubPort", "to_sub_port_range"]),  # Not required for querying all objects and deleting sub port blocks
        from_card=dict(type="str", aliases=["from_card_range"]),
        to_card=dict(type="str", aliases=["to_card_range"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["access_port_selector", "leaf_port_blk", "leaf_interface_profile"]],
            ["state", "present", ["access_port_selector", "leaf_port_blk", "from_port", "to_port", "from_sub_port", "to_sub_port", "leaf_interface_profile"]],
        ],
    )

    leaf_interface_profile = module.params.get("leaf_interface_profile")
    access_port_selector = module.params.get("access_port_selector")
    leaf_port_blk = module.params.get("leaf_port_blk")
    leaf_port_blk_description = module.params.get("leaf_port_blk_description")
    from_port = module.params.get("from_port")
    to_port = module.params.get("to_port")
    from_sub_port = module.params.get("from_sub_port")
    to_sub_port = module.params.get("to_sub_port")
    from_card = module.params.get("from_card")
    to_card = module.params.get("to_card")
    state = module.params.get("state")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="infraAccPortP",
            aci_rn="infra/accportprof-{0}".format(leaf_interface_profile),
            module_object=leaf_interface_profile,
            target_filter={"name": leaf_interface_profile},
        ),
        subclass_1=dict(
            aci_class="infraHPortS",
            # NOTE: normal rn: hports-{name}-typ-{type}, hence here hardcoded to range for purposes of module
            aci_rn="hports-{0}-typ-range".format(access_port_selector),
            module_object=access_port_selector,
            target_filter={"name": access_port_selector},
        ),
        subclass_2=dict(
            aci_class="infraSubPortBlk",
            aci_rn="subportblk-{0}".format(leaf_port_blk),
            module_object=leaf_port_blk,
            target_filter={"name": leaf_port_blk},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="infraSubPortBlk",
            class_config=dict(
                descr=leaf_port_blk_description,
                name=leaf_port_blk,
                fromPort=from_port,
                toPort=to_port,
                fromSubPort=from_sub_port,
                toSubPort=to_sub_port,
                fromCard=from_card,
                toCard=to_card,
                #  type='range',
            ),
        )

        aci.get_diff(aci_class="infraSubPortBlk")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
