#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l3out_floating_svi
short_description: Manage Layer 3 Outside (L3Out) interfaces (l3ext:RsPathL3OutAtt)
description:
- Manage L3Out interfaces on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
    required: true
  l3out:
    description:
    - Name of an existing L3Out.
    type: str
    aliases: [ l3out_name ]
    required: true
  node_profile:
    description:
    - Name of the node profile.
    type: str
    aliases: [ node_profile_name, logical_node ]
    required: true
  interface_profile:
    description:
    - Name of the interface profile.
    type: str
    aliases: [ interface_profile_name, logical_interface ]
    required: true
  pod_id:
    description:
    - Pod to build the interface on.
    type: str
  node_id:
    description:
    - Node to build the interface on for Port-channels and single ports.
    - Hyphen separated pair of nodes (e.g. "201-202") for vPCs.
    type: str
  path_ep:
    description:
    - Path to interface
    - Interface Policy Group name for Port-channels and vPCs
    - Port number for single ports (e.g. "eth1/12")
    type: str
  encap:
    description:
    - encapsulation on the interface (e.g. "vlan-500")
    type: str
  address:
    description:
    - IP address.
    type: str
    aliases: [ addr, ip_address]
  mtu:
    description:
    - Interface MTU.
    type: str
  ipv6_dad:
    description:
    - IPv6 DAD feature.
    type: str
    choices: [ enabled, disabled]
  interface_type:
    description:
    - Type of interface to build.
    type: str
    choices: [ l3-port, sub-interface, ext-svi ]
  mode:
    description:
    - Interface mode, only used if instance_type is ext-svi
    type: str
    choices: [ regular, native, untagged ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  auto_state:
    description:
    - SVI auto state.
    type: str
    choices: [ enabled, disabled ]
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

seealso:
- module: aci_l3out
- module: aci_l3out_logical_node_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l3ext:RsPathL3OutAtt)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Marcel Zehnder (@maercu)
"""

EXAMPLES = r"""
- name: Add a new routed interface
  cisco.aci.aci_l3out_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    path_ep: eth1/12
    interface_type: l3-port
    address: 192.168.10.1/27
    state: present
  delegate_to: localhost

- name: Add a new SVI vPC
  cisco.aci.aci_l3out_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201-202
    path_ep: my_vpc_ipg
    interface_type: ext-svi
    encap: vlan-800
    mode: regular
    state: present
  delegate_to: localhost

- name: Delete an interface
  cisco.aci.aci_l3out_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    path_ep: eth1/12
    state: absent
  delegate_to: localhost

- name: Query an interface
  cisco.aci.aci_l3out_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    path_ep: eth1/12
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
        tenant=dict(type="str", aliases=["tenant_name"], required=True),
        l3out=dict(type="str", aliases=["l3out_name"], required=True),
        node_profile=dict(type="str", aliases=["node_profile_name", "logical_node"], required=True),
        interface_profile=dict(type="str", aliases=["interface_profile_name", "logical_interface"], required=True),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        pod_id=dict(type="str"),
        node_id=dict(type="str"),
        address=dict(type="str", aliases=["addr", "ip_address"]),
        link_local_address=dict(type="str"),
        mac_address=dict(type="str"),
        mtu=dict(type="str"),
        ipv6_dad=dict(type="str", choices=["enabled", "disabled"]),
        mode=dict(type="str", choices=["regular", "native", "untagged"]),
        encap=dict(type="str"),
        encap_scope=dict(type="str", choices=["vrf", "local"]),
        auto_state=dict(type="str", choices=["enabled", "disabled"]),
        description=dict(type="str", aliases=["descr"]),
        external_bridge_group_profile=dict(type="str"),
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
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[["state", "present", ["pod_id", "node_id", "encap", "address"]], ["state", "absent", ["pod_id", "node_id", "encap"]]],
    )

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    node_profile = module.params.get("node_profile")
    interface_profile = module.params.get("interface_profile")
    state = module.params.get("state")
    pod_id = module.params.get("pod_id")
    node_id = module.params.get("node_id")
    address = module.params.get("address")
    mtu = module.params.get("mtu")
    ipv6_dad = module.params.get("ipv6_dad")
    mode = module.params.get("mode")
    encap = module.params.get("encap")
    encap_scope = "ctx" if module.params.get("encap_scope") == "vrf" else module.params.get("encap_scope")
    auto_state = module.params.get("auto_state")
    external_bridge_group_profile = module.params.get("external_bridge_group_profile")

    aci = ACIModule(module)

    node_dn = "topology/pod-{0}/node-{1}".format(pod_id, node_id)

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
            aci_class="l3extLIfP",
            aci_rn="lifp-{0}".format(interface_profile),
            module_object=interface_profile,
            target_filter={"name": interface_profile},
        ),
        subclass_4=dict(
            aci_class="l3extVirtualLIfP", aci_rn="vlifp-[{0}]-[{1}]".format(node_dn, encap), module_object=node_dn, target_filter={"nodeDn": node_dn}
        ),
        child_classes=["l3extBdProfileCont"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if external_bridge_group_profile is not None:
            if external_bridge_group_profile == "" and isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("l3extVirtualLIfP", {}).get("children", {}):
                    if child.get("l3extBdProfileCont"):
                        child_configs.append(
                            dict(
                                l3extBdProfileCont=dict(
                                    attributes=dict(status="deleted"),
                                ),
                            )
                        )
            elif external_bridge_group_profile != "":
                child_configs.append(
                    dict(
                        l3extBdProfileCont=dict(
                            attributes=dict(),
                            children=[
                                dict(
                                    l3extRsBdProfile=dict(
                                        attributes=dict(
                                            tDn="uni/tn-{0}/bdprofile-{1}".format(tenant, external_bridge_group_profile),
                                        ),
                                    )
                                )
                            ],
                        )
                    )
                )

        aci.payload(
            aci_class="l3extVirtualLIfP",
            class_config=dict(
                addr=address, ipv6Dad=ipv6_dad, mtu=mtu, ifInstT="ext-svi", mode=mode, encap=encap, encapScope=encap_scope, autostate=auto_state
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="l3extVirtualLIfP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
