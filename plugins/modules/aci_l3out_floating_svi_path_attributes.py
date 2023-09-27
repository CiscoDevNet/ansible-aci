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
        pod_id=dict(type="str", required=True),
        node_id=dict(type="str", required=True),
        encap=dict(type="str", required=True),
        floating_ip=dict(type="str", aliases=["floating_address"], required=True),
        forged_transmit=dict(type="str", choices=["enabled", "disabled"]),
        mac_change=dict(type="str", choices=["enabled", "disabled"]),
        promiscuous_mode=dict(type="str", choices=["enabled", "disabled"]),
        domain_type=dict(type="str", choices=["physical", "virtual"], required=True),
        domain=dict(type="str", required=True),
        enhanced_lag_policy=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[["state", "present", ["domain_type", "domain", "floating_ip"]], ["state", "absent", ["domain_type", "domain"]]],
    )

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    node_profile = module.params.get("node_profile")
    interface_profile = module.params.get("interface_profile")
    state = module.params.get("state")
    pod_id = module.params.get("pod_id")
    node_id = module.params.get("node_id")
    floating_ip = module.params.get("floating_ip")
    encap = module.params.get("encap")
    forged_transmit = module.params.get("forged_transmit")
    mac_change = module.params.get("mac_change")
    promiscuous_mode = module.params.get("promiscuous_mode")
    domain_type = module.params.get("domain_type")
    domain = module.params.get("domain")
    enhanced_lag_policy = module.params.get("enhanced_lag_policy")
    
    aci = ACIModule(module)

    node_dn = "topology/pod-{0}/node-{1}".format(pod_id, node_id)

    if domain_type == "physical":
        tDn = "uni/phys-{0}".format(domain)            
    else:
        tDn = "uni/vmmp-VMware/dom-{0}".format(domain)

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
        subclass_5=dict(
            aci_class="l3extRsDynPathAtt",
            aci_rn="rsdynPathAtt-[{0}]".format(tDn),
            module_object=tDn,
            target_filter={"tDn": tDn},
        ),
        child_classes=["l3extVirtualLIfPLagPolAtt"]
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if enhanced_lag_policy is not None and domain_type == "virtual":
            existing_enhanced_lag_policy = ""
            if isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("l3extRsDynPathAtt", {}).get("children", {}):
                    if child.get("l3extVirtualLIfPLagPolAtt"):
                        existing_enhanced_lag_policy = (
                            child.get("l3extVirtualLIfPLagPolAtt").get("children")[0].get("l3extRsVSwitchEnhancedLagPol").get("attributes").get("tDn").split("enlacplagp-")[1]
                        )
                        if enhanced_lag_policy == "":
                            child_configs.append(
                                dict(
                                    l3extVirtualLIfPLagPolAtt=dict(
                                        attributes=dict(status="deleted"),
                                    ),
                                )
                            )

            if enhanced_lag_policy != "":
                child=[
                      dict(
                          l3extRsVSwitchEnhancedLagPol=dict(
                              attributes=dict(
                                  tDn="{0}/vswitchpolcont/enlacplagp-{1}".format(tDn, enhanced_lag_policy)
                              ),
                          )
                      ),
                    ]
                if enhanced_lag_policy != existing_enhanced_lag_policy and existing_enhanced_lag_policy != "":
                    child.append(
                            dict(
                                l3extRsVSwitchEnhancedLagPol=dict(
                                    attributes=dict(
                                        status="deleted",
                                        tDn="{0}/vswitchpolcont/enlacplagp-{1}".format(tDn, existing_enhanced_lag_policy)
                                    ),
                                )
                            )
                    )
                child_configs.append(
                    dict(
                        l3extVirtualLIfPLagPolAtt=dict(
                            attributes=dict(),
                            children=child
                        )
                    )
                )

        aci.payload(
            aci_class="l3extRsDynPathAtt",
            class_config=dict(
                floatingAddr=floating_ip, forgedTransmit=forged_transmit, macChange=mac_change, promMode=promiscuous_mode,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="l3extRsDynPathAtt")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
