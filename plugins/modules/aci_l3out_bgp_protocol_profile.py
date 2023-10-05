#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_l3out_route_tag_policy
short_description: Manage BGP Protocol Profile (bgp:ProtP)
description:
- Manage BGP Protocol Profile for The Logical Node Profiles on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l3out:
    description:
    - The name of an existing L3Out.
    type: str
    aliases: [ l3out_name ]
  node_profile:
    description:
    - The name of an existing logical node profile.
    type: str
    aliases: [ node_profile_name, logical_node ]
  bgp_protocol_profile:
    description:
    - The name of the bgp protocol profile.
    type: str
    aliases: [ name, bgp_protocol_profile_name ]
  bgp_timers_policy:
    description:
    - The name of an existing bgp timers policy.
    type: str
    aliases: [ bgp_timers_policy_name ]
  bgp_best_path_policy:
    description:
    - The name of the bgp best path control policy.
    type: str
    aliases: [ bgp_best_path_policy_name ]
  description:
    description:
    - Description for the bgp protocol profile.
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

notes:
- The C(tenant) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(bgp:ProtP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Dag Wieers (@dagwieers)
"""

EXAMPLES = r"""
- name: Create a l3out route tag policy
  cisco.aci.aci_l3out_route_tag_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tag: 1000
    bgp_protocol_profile: my_route_tag_policy
    tenant: production
    state: present
  delegate_to: localhost

- name: Delete a l3out route tag policy
  cisco.aci.aci_l3out_route_tag_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    bgp_protocol_profile: my_route_tag_policy
    tenant: production
    state: absent
  delegate_to: localhost

- name: Query all l3out route tag policies
  cisco.aci.aci_l3out_route_tag_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific l3out route tag policy
  cisco.aci.aci_l3out_route_tag_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    bgp_protocol_profile: my_route_tag_policy
    tenant: production
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
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        l3out=dict(type="str", aliases=["l3out_name"]),  # Not required for querying all objects
        node_profile=dict(type="str", aliases=["node_profile_name", "logical_node"]),  # Not required for querying all objects
        bgp_protocol_profile=dict(type="str", aliases=["name", "bgp_protocol_profile_name"]),  # Not required for querying all objects
        bgp_timers_policy=dict(type="str", aliases=["bgp_timers_policy_name"]),
        bgp_best_path_policy=dict(type="str", aliases=["bgp_best_path_policy_name"]),
        description=dict(type="str", aliases=["descr"]),
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

    bgp_protocol_profile = module.params.get("bgp_protocol_profile")
    bgp_timers_policy = module.params.get("bgp_timers_policy")
    bgp_best_path_policy = module.params.get("bgp_best_path_policy")
    description = module.params.get("description")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    node_profile = module.params.get("node_profile")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)

    child_classes = ["bgpRsBgpNodeCtxPol", "bgpRsBestPathCtrlPol"]

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
        subclass_3=dict(
            aci_class="bgpProtP",
            aci_rn="protp",
            module_object="",
            target_filter={"name": bgp_protocol_profile},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs=[]
        if bgp_timers_policy is not None:
            child_configs.append(dict(bgpRsBgpNodeCtxPol=dict(attributes=dict(tnBgpCtxPolName=bgp_timers_policy))))
        if bgp_best_path_policy is not None:
            child_configs.append(
                dict(bgpRsBestPathCtrlPo=dict(attributes=dict(tnBgpBestPathCtrlPolName=bgp_timers_policy)))
            )

        aci.payload(
            aci_class="bgpProtP",
            class_config=dict(
                name=bgp_protocol_profile,
                descr=description,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="bgpProtP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()