#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Bruno Calogero <brunocalogero@hotmail.com>
# Copyright: (c) 2023, Eric Girard <@netgirard>
# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "certified",
}

DOCUMENTATION = r"""
---
module: aci_switch_spine_selector
short_description: Bind spine selectors to switch policy spine profiles (infra:SpineS, infra:NodeBlk, infra:RsSpineAccNodePGrep)
description:
- Bind spine selectors (with node block range and policy group) to switch policy spine profiles on Cisco ACI fabrics.
options:
  description:
    description:
    - The description to assign to the C(spine).
    type: str
  spine_profile:
    description:
    - The name of the Spine Profile to which we add a Selector.
    type: str
    aliases: [ spine_profile_name ]
  spine:
    description:
    - The name of Spine Selector.
    type: str
    aliases: [ name, spine_name, spine_profile_spine_name, spine_selector_name ]
  spine_node_blk:
    description:
    - The name of Node Block range to be added to Spine Selector of given Spine Profile.
    type: str
    aliases: [ spine_node_blk_name, node_blk_name ]
  spine_node_blk_description:
    description:
    - The description to assign to the C(spine_node_blk)
    type: str
  from:
    description:
    - The start of Node Block range.
    type: int
    aliases: [ node_blk_range_from, from_range, range_from ]
  to:
    description:
    - The end of Node Block range.
    type: int
    aliases: [ node_blk_range_to, to_range, range_to ]
  policy_group:
    description:
    - The name of the Policy Group to be added to Spine Selector of given Spine Profile.
    type: str
    aliases: [ name, policy_group_name ]
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

notes:
- This module is to be used with M(cisco.aci.aci_switch_policy_spine_profile).
  One first creates a spine profile (infra:SpineP) and then creates an associated selector (infra:SpineS),
seealso:
- module: cisco.aci.aci_switch_policy_spine_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(infra:SpineS),
               B(infra:NodeBlk) and B(infra:RsAccNodePGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Bruno Calogero (@brunocalogero)
- Eric Girard (@netgirard)
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Add a switch policy spine profile selector associated Node Block range (with policy group)
  cisco.aci.aci_switch_spine_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    spine_profile: sw_name
    spine: spine_selector_name
    spine_node_blk: node_blk_name
    from: 1011
    to: 1011
    policy_group: somepolicygroupname
    state: present
  delegate_to: localhost

- name: Add a switch policy spine profile selector associated Node Block range (without policy group)
  cisco.aci.aci_switch_spine_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    spine_profile: sw_name
    spine: spine_selector_name
    spine_node_blk: node_blk_name
    from: 1011
    to: 1011
    state: present
  delegate_to: localhost

- name: Query a switch policy spine profile selector
  cisco.aci.aci_switch_spine_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    spine_profile: sw_name
    spine: spine_selector_name
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all switch policy spine profile selectors
  cisco.aci.aci_switch_spine_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove a switch policy spine profile selector
  cisco.aci.aci_switch_spine_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    spine_profile: sw_name
    spine: spine_selector_name
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
        {
            "description": dict(type="str"),
            "spine_profile": dict(
                type="str", aliases=["spine_profile_name"]
            ),  # Not required for querying all objects
            "spine": dict(
                type="str",
                aliases=[
                    "name",
                    "spine_name",
                    "spine_profile_spine_name",
                    "spine_selector_name",
                ],
            ),  # Not required for querying all objects
            "spine_node_blk": dict(
                type="str", aliases=["spine_node_blk_name", "node_blk_name"]
            ),
            "spine_node_blk_description": dict(type="str"),
            # NOTE: Keyword 'from' is a reserved word in python, so we need it as a string
            "from": dict(
                type="int", aliases=["node_blk_range_from", "from_range", "range_from"]
            ),
            "to": dict(
                type="int", aliases=["node_blk_range_to", "to_range", "range_to"]
            ),
            "policy_group": dict(type="str", aliases=["policy_group_name"]),
            "state": dict(
                type="str", default="present", choices=["absent", "present", "query"]
            ),
            "name_alias": dict(type="str"),
        }
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["spine_profile", "spine"]],
            [
                "state",
                "present",
                ["spine_profile", "spine", "spine_node_blk", "from", "to"],
            ],
        ],
    )

    description = module.params.get("description")
    spine_profile = module.params.get("spine_profile")
    spine = module.params.get("spine")
    spine_node_blk = module.params.get("spine_node_blk")
    spine_node_blk_description = module.params.get("spine_node_blk_description")
    from_ = module.params.get("from")
    to_ = module.params.get("to")
    policy_group = module.params.get("policy_group")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    # Build child_configs dynamically
    child_configs = [
        dict(
            infraNodeBlk=dict(
                attributes=dict(
                    descr=spine_node_blk_description,
                    name=spine_node_blk,
                    from_=from_,
                    to_=to_,
                ),
            ),
        ),
    ]

    # Add infraRsAccNodePGrp only when policy_group was defined
    if policy_group is not None:
        child_configs.append(
            dict(
                infraRsSpineAccNodePGrp=dict(
                    attributes=dict(
                        tDn="uni/infra/funcprof/spaccnodepgrp-{0}".format(policy_group),
                    ),
                ),
            )
        )

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="infraInfra",
            aci_rn="infra",
        ),
        subclass_1=dict(
            aci_class="infraSpineP",
            aci_rn="spprof-{0}".format(spine_profile),
            module_object=spine_profile,
            target_filter={"name": spine_profile},
        ),
        subclass_2=dict(
            aci_class="infraSpineS",
            # NOTE: normal rn: spines-{name}-typ-{type}, hence here hardcoded to range for purposes of module
            aci_rn="spines-{0}-typ-range".format(spine),
            module_object=spine,
            target_filter={"name": spine},
        ),
        # NOTE: infraNodeBlk is not made into a subclass because there is a 1-1 mapping between node block and spine selector name
        child_classes=["infraNodeBlk", "infraRsSpineAccNodePGrp"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="infraSpineS",
            class_config=dict(
                descr=description,
                name=spine,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="infraSpineS")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
