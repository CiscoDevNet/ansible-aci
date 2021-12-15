#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Bruno Calogero <brunocalogero@hotmail.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_switch_leaf_selector
short_description: Bind leaf selectors to switch policy leaf profiles (infra:LeafS, infra:NodeBlk, infra:RsAccNodePGrep)
description:
- Bind leaf selectors (with node block range and policy group) to switch policy leaf profiles on Cisco ACI fabrics.
options:
  description:
    description:
    - The description to assign to the C(leaf).
    type: str
  leaf_profile:
    description:
    - Name of the Leaf Profile to which we add a Selector.
    type: str
    aliases: [ leaf_profile_name ]
  leaf:
    description:
    - Name of Leaf Selector.
    type: str
    aliases: [ name, leaf_name, leaf_profile_leaf_name, leaf_selector_name ]
  leaf_node_blk:
    description:
    - Name of Node Block range to be added to Leaf Selector of given Leaf Profile.
    type: str
    aliases: [ leaf_node_blk_name, node_blk_name ]
  leaf_node_blk_description:
    description:
    - The description to assign to the C(leaf_node_blk)
    type: str
  from:
    description:
    - Start of Node Block range.
    type: int
    aliases: [ node_blk_range_from, from_range, range_from ]
  to:
    description:
    - Start of Node Block range.
    type: int
    aliases: [ node_blk_range_to, to_range, range_to ]
  policy_group:
    description:
    - Name of the Policy Group to be added to Leaf Selector of given Leaf Profile.
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
- This module is to be used with M(cisco.aci.aci_switch_policy_leaf_profile).
  One first creates a leaf profile (infra:NodeP) and then creates an associated selector (infra:LeafS),
seealso:
- module: cisco.aci.aci_switch_policy_leaf_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(infra:LeafS),
               B(infra:NodeBlk) and B(infra:RsAccNodePGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Bruno Calogero (@brunocalogero)
"""

EXAMPLES = r"""
- name: adding a switch policy leaf profile selector associated Node Block range (w/ policy group)
  cisco.aci.aci_switch_leaf_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    leaf_profile: sw_name
    leaf: leaf_selector_name
    leaf_node_blk: node_blk_name
    from: 1011
    to: 1011
    policy_group: somepolicygroupname
    state: present
  delegate_to: localhost

- name: adding a switch policy leaf profile selector associated Node Block range (w/o policy group)
  cisco.aci.aci_switch_leaf_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    leaf_profile: sw_name
    leaf: leaf_selector_name
    leaf_node_blk: node_blk_name
    from: 1011
    to: 1011
    state: present
  delegate_to: localhost

- name: Removing a switch policy leaf profile selector
  cisco.aci.aci_switch_leaf_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    leaf_profile: sw_name
    leaf: leaf_selector_name
    state: absent
  delegate_to: localhost

- name: Querying a switch policy leaf profile selector
  cisco.aci.aci_switch_leaf_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    leaf_profile: sw_name
    leaf: leaf_selector_name
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
        {
            "description": dict(type="str"),
            "leaf_profile": dict(type="str", aliases=["leaf_profile_name"]),  # Not required for querying all objects
            "leaf": dict(type="str", aliases=["name", "leaf_name", "leaf_profile_leaf_name", "leaf_selector_name"]),  # Not required for querying all objects
            "leaf_node_blk": dict(type="str", aliases=["leaf_node_blk_name", "node_blk_name"]),
            "leaf_node_blk_description": dict(type="str"),
            # NOTE: Keyword 'from' is a reserved word in python, so we need it as a string
            "from": dict(type="int", aliases=["node_blk_range_from", "from_range", "range_from"]),
            "to": dict(type="int", aliases=["node_blk_range_to", "to_range", "range_to"]),
            "policy_group": dict(type="str", aliases=["policy_group_name"]),
            "state": dict(type="str", default="present", choices=["absent", "present", "query"]),
            "name_alias": dict(type="str"),
        }
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[["state", "absent", ["leaf_profile", "leaf"]], ["state", "present", ["leaf_profile", "leaf", "leaf_node_blk", "from", "to"]]],
    )

    description = module.params.get("description")
    leaf_profile = module.params.get("leaf_profile")
    leaf = module.params.get("leaf")
    leaf_node_blk = module.params.get("leaf_node_blk")
    leaf_node_blk_description = module.params.get("leaf_node_blk_description")
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
                    descr=leaf_node_blk_description,
                    name=leaf_node_blk,
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
                infraRsAccNodePGrp=dict(
                    attributes=dict(
                        tDn="uni/infra/funcprof/accnodepgrp-{0}".format(policy_group),
                    ),
                ),
            )
        )

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="infraNodeP",
            aci_rn="infra/nprof-{0}".format(leaf_profile),
            module_object=leaf_profile,
            target_filter={"name": leaf_profile},
        ),
        subclass_1=dict(
            aci_class="infraLeafS",
            # NOTE: normal rn: leaves-{name}-typ-{type}, hence here hardcoded to range for purposes of module
            aci_rn="leaves-{0}-typ-range".format(leaf),
            module_object=leaf,
            target_filter={"name": leaf},
        ),
        # NOTE: infraNodeBlk is not made into a subclass because there is a 1-1 mapping between node block and leaf selector name
        child_classes=["infraNodeBlk", "infraRsAccNodePGrp"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="infraLeafS",
            class_config=dict(
                descr=description,
                name=leaf,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="infraLeafS")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
