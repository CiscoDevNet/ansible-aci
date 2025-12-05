#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, based on aci_bulk_static_binding_epg
# Copyright: (c) 2025, Andreas Graber (@andreasgraber) <graber@netcloud.ch>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_bulk_static_bindings_to_epgs
short_description: Bind List of static paths to EPGs (fv:RsPathAtt)
description:
- Bind List of static paths to EPGs on Cisco ACI fabrics.
options:
  static_bindings:
    description:
    - List of EPGs in the form of a dictionary.
    type: list
    elements: dict
    suboptions:
      tenant:
        description:
        - Name of the tenant.
        type: str
        aliases: [ tenant_name ]
        required: True
      ap:
        description:
        - The name of the application profile.
        type: str
        aliases: [ app_profile, app_profile_name ]
        required: True
      epg:
        description:
        - The name of the end point group.
        type: str
        aliases: [ epg_name ]
        required: True
      description:
        description:
        - Description for the static path to EPG binding.
        type: str
        aliases: [ descr ]
      encap_id:
        description:
        - The encapsulation ID associating the C(epg) with the interface path.
        - This acts as the secondary C(encap_id) when using micro-segmentation.
        - Accepted values are any valid encap ID for specified encap, currently ranges between C(1) and C(4096).
        type: int
        aliases: [ vlan, vlan_id ]
        required: True
      primary_encap_id:
        description:
        - Determines the primary encapsulation ID associating the C(epg)
          with the interface path when using micro-segmentation.
        - Accepted values are any valid encap ID for specified encap, currently ranges between C(1) and C(4096) and C(unknown).
        - C(unknown) is the default value and using C(unknown) disables the Micro-Segmentation.
        type: str
        aliases: [ primary_vlan, primary_vlan_id ]
      deploy_immediacy:
        description:
        - The Deployment Immediacy of Static EPG on PC, VPC or Interface.
        - The APIC defaults to C(lazy) when unset during creation.
        type: str
        choices: [ immediate, lazy ]
      interface_mode:
        description:
        - Determines how layer 2 tags will be read from and added to frames.
        - Values C(802.1p) and C(native) are identical.
        - Values C(access) and C(untagged) are identical.
        - Values C(regular), C(tagged) and C(trunk) are identical.
        - The APIC defaults to C(trunk) when unset during creation.
        type: str
        choices: [ 802.1p, access, native, regular, tagged, trunk, untagged ]
        aliases: [ interface_mode_name, mode ]
  interface_configs:
    description:
    - List of interface configurations, elements in the form of a dictionary.
    type: list
    elements: dict
    suboptions:
      interface_type:
        description:
        - The type of interface for the static EPG deployment.
        type: str
        choices: [ fex, port_channel, switch_port, vpc, fex_port_channel, fex_vpc ]
      pod_id:
        description:
        - The pod number part of the tDn.
        - C(pod_id) is usually an integer below C(10).
        type: int
        required: true
        aliases: [ pod, pod_number ]
      leafs:
        description:
        - The switch ID(s) that the C(interface) belongs to.
        - When C(interface_type) is C(switch_port), C(port_channel), or C(fex), then C(leafs) is a string of the leaf ID.
        - When C(interface_type) is C(vpc), then C(leafs) is a list with both leaf IDs.
        - The C(leafs) value is usually something like '101' or '101-102' depending on C(connection_type).
        type: list
        elements: str
        required: true
        aliases: [ leaves, nodes, paths, switches ]
      interface:
        description:
        - The C(interface) string value part of the tDn.
        - Usually a policy group like C(test-IntPolGrp) or an interface of the following format C(1/7) depending on C(interface_type).
        type: str
        required: true
      extpaths:
        description:
        - The C(extpaths) integer value part of the tDn.
        - C(extpaths) is only used if C(interface_type) is C(fex), C(fex_vpc) or C(fex_port_channel).
        - When C(interface_type) is C(fex_vpc), then C(extpaths) is a list with both fex IDs.
        - Usually something like C(1011).
        type: list
        elements: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    type: str
    choices: [ absent, present ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- The C(tenant), C(ap), C(epg) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_ap), M(cisco.aci.aci_epg) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_ap
- module: cisco.aci.aci_epg
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:RsPathAtt).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- based on aci_bulk_static_binding
- Andreas Graber (@andreasgraber)
"""

EXAMPLES = r"""
- name: Create Static Bindings on a list of Interfaces
  cisco.aci.aci_bulk_static_bindings_to_epgs:
    host: apic
    username: admin
    password: SomeSecretPassword
    static_bindings:
      - tenant: accessport-code-cert
        ap: accessport_code_app
        epg: accessport_epg1
        encap_id: 221
        interface_mode: trunk
        deploy_immediacy: lazy
        description: "First Binding"
      - tenant: accessport-code-cert-2
        ap: accessport_code_app_2
        epg: accessport_epg2
        encap_id: 221
        interface_mode: trunk
        deploy_immediacy: lazy
        description: "Second Binding"
    interface_configs:
      - interface: 1/7
        leafs: 101
        pod: 1
        interface_type: switch_port
      - interface: 1/7
        leafs: 107
        pod: 7
        interface_type: switch_port
      - interface: 1/8
        leafs: 108
        pod: 8
        encap_id: 108
        interface_type: switch_port
    state: present
  delegate_to: localhost

- name: Remove Static Bindings on a list of Interfaces
  cisco.aci.aci_bulk_static_bindings_to_epgs:
    host: apic
    username: admin
    password: SomeSecretPassword
    static_bindings:
      - tenant: accessport-code-cert
        ap: accessport_code_app
        epg: accessport_epg1
        encap_id: 221
        interface_mode: trunk
        deploy_immediacy: lazy
        description: "First Binding"
      - tenant: accessport-code-cert-2
        ap: accessport_code_app_2
        epg: accessport_epg2
        encap_id: 221
        interface_mode: trunk
        deploy_immediacy: lazy
        description: "Second Binding"
    interface_configs:
      - interface: 1/7
        leafs: 101
        pod: 1
      - interface: 1/7
        leafs: 107
        pod: 7
      - interface: 1/8
        leafs: 108
        pod: 8
        encap_id: 108
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec

INTERFACE_MODE_MAPPING = {
    "802.1p": "native",
    "access": "untagged",
    "native": "native",
    "regular": "regular",
    "tagged": "regular",
    "trunk": "regular",
    "untagged": "untagged",
}

INTERFACE_TYPE_MAPPING = {
    "fex": "topology/pod-{pod_id}/paths-{leafs}/extpaths-{extpaths}/pathep-[eth{interface}]",
    "fex_port_channel": "topology/pod-{pod_id}/paths-{leafs}/extpaths-{extpaths}/pathep-[{interface}]",
    "fex_vpc": "topology/pod-{pod_id}/protpaths-{leafs}/extprotpaths-{extpaths}/pathep-[{interface}]",
    "port_channel": "topology/pod-{pod_id}/paths-{leafs}/pathep-[{interface}]",
    "switch_port": "topology/pod-{pod_id}/paths-{leafs}/pathep-[eth{interface}]",
    "vpc": "topology/pod-{pod_id}/protpaths-{leafs}/pathep-[{interface}]",
}

INTERFACE_STATUS_MAPPING = {"absent": "deleted"}


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        static_bindings=dict(
            type="list",
            elements="dict",
            options=dict(
                tenant=dict(type="str", aliases=["tenant_name"]),
                ap=dict(type="str", aliases=["app_profile", "app_profile_name"]),
                epg=dict(type="str", aliases=["epg_name"]),
                description=dict(type="str", aliases=["descr"]),
                encap_id=dict(type="int", aliases=["vlan", "vlan_id"]),
                primary_encap_id=dict(type="str", aliases=["primary_vlan", "primary_vlan_id"]),
                deploy_immediacy=dict(type="str", choices=["immediate", "lazy"]),
                interface_mode=dict(
                    type="str", choices=["802.1p", "access", "native", "regular", "tagged", "trunk", "untagged"],
                    aliases=["interface_mode_name", "mode"]
                ))),
        interface_type=dict(type="str", default="switch_port",
                            choices=["fex", "port_channel", "switch_port", "vpc", "fex_port_channel", "fex_vpc"]),
        interface_configs=dict(
            type="list",
            elements="dict",
            options=dict(
                description=dict(type="str", aliases=["descr"]),
                interface_type=dict(type="str",
                                    choices=["fex", "port_channel", "switch_port", "vpc", "fex_port_channel",
                                             "fex_vpc"]),
                pod_id=dict(type="int", required=True, aliases=["pod", "pod_number"]),
                leafs=dict(type="list", elements="str", required=True,
                           aliases=["leaves", "nodes", "paths", "switches"]),
                interface=dict(type="str", required=True),
                extpaths=dict(type="list", elements="str"),
            ),
        ),
        state=dict(type="str", default="present", choices=["absent", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["static_bindings", "interface_configs"]],
            ["state", "present", ["static_bindings", "interface_configs"]],
        ],
    )

    static_bindings = module.params.get("static_bindings")
    interface_configs = module.params.get("interface_configs")
    state = module.params.get("state")

    aci = ACIModule(module)
    children = []


    aci.construct_url(
        root_class=dict(
            aci_class="polUni",
            aci_rn="",
            module_object="",
            child_classes=["fvTenant"]

        ),
        child_classes=["fvRsPathAtt"]
    )

    aci.get_existing()

    if state == "present" or state == "absent":
        for binding in static_bindings:
            tenant = binding.get("tenant")
            ap = binding.get("ap")
            epg = binding.get("epg")
            module_description = binding.get("description")
            module_encap_id = binding.get("encap_id")
            module_primary_encap_id = binding.get("primary_encap_id")
            module_deploy_immediacy = binding.get("deploy_immediacy")
            module_interface_mode = binding.get("interface_mode")

            for interface_config in interface_configs:
                pod_id = interface_config.get("pod_id")
                interface = interface_config.get("interface")
                extpaths = interface_config.get("extpaths")
                interface_type = interface_config.get("interface_type", "switch_port")

                description = interface_config.get("description") or module_description

                if interface_type in ["fex", "fex_vpc", "fex_port_channel"] and extpaths is None:
                    aci.fail_json(msg="extpaths is required when interface_type is: {0}".format(interface_type))

                # Process leafs, and support dash-delimited leafs
                leafs = []
                for leaf in interface_config.get("leafs"):
                    # Users are likely to use integers for leaf IDs, which would raise an exception when using the join method
                    leafs.extend(str(leaf).split("-"))
                if len(leafs) == 1:
                    if interface_type in ["vpc", "fex_vpc"]:
                        aci.fail_json(msg='A interface_type of "vpc" requires 2 leafs')
                    leafs = leafs[0]
                elif len(leafs) == 2:
                    if interface_type not in ["vpc", "fex_vpc"]:
                        aci.fail_json(
                            msg='The interface_types "switch_port", "port_channel", and "fex" do not support using multiple leafs for a single binding')
                    leafs = "-".join(leafs)
                else:
                    aci.fail_json(msg='The "leafs" parameter must not have more than 2 entries')

                if extpaths is not None:
                    # Process extpaths, and support dash-delimited extpaths
                    extpaths = []
                    for extpath in interface_config.get("extpaths"):
                        # Users are likely to use integers for extpaths IDs, which would raise an exception when using the join method
                        extpaths.extend(str(extpath).split("-"))
                    if len(extpaths) == 1:
                        if interface_type == "fex_vpc":
                            aci.fail_json(msg='A interface_type of "fex_vpc" requires 2 extpaths')
                        extpaths = extpaths[0]
                    elif len(extpaths) == 2:
                        if interface_type != "fex_vpc":
                            aci.fail_json(
                                msg='The interface_types "fex" and "fex_port_channel" do not support using multiple extpaths for a single binding')
                        extpaths = "-".join(extpaths)
                    else:
                        aci.fail_json(msg='The "extpaths" parameter must not have more than 2 entries')

                if module_encap_id not in range(1, 4097):
                    aci.fail_json(msg="Valid VLAN assignments are from 1 to 4096")
                encap_id = "vlan-{0}".format(module_encap_id)

                if module_primary_encap_id is not None:
                    try:
                        primary_encap_id = int(module_primary_encap_id)
                        if isinstance(primary_encap_id, int) and primary_encap_id in range(1, 4097):
                            primary_encap_id = "vlan-{0}".format(primary_encap_id)
                        else:
                            aci.fail_json(msg="Valid VLAN assignments are from 1 to 4096 or unknown.")
                    except Exception as e:
                        if isinstance(module_primary_encap_id, str) and module_primary_encap_id != "unknown":
                            aci.fail_json(msg="Valid VLAN assignments are from 1 to 4096 or unknown. %s" % e)

                static_path = INTERFACE_TYPE_MAPPING[interface_type].format(pod_id=pod_id,
                                                                            leafs=leafs,
                                                                            extpaths=extpaths,
                                                                            interface=interface)

                interface_mode = INTERFACE_MODE_MAPPING.get(module_interface_mode)

                interface_status = INTERFACE_STATUS_MAPPING.get(state)
                binding_to_push = dict(fvRsPathAtt=dict(
                    attributes=dict(
                        descr=description,
                        encap=encap_id,
                        primaryEncap=module_primary_encap_id,
                        instrImedcy=module_deploy_immediacy,
                        mode=interface_mode,
                        tDn=static_path,
                        status=interface_status,
                    )
                )
                )

                epg_to_push = dict(
                            fvAEPg=dict(
                                attributes=dict(
                                    name=epg
                                ),
                                children=[binding_to_push]
                                , )
                        )

                ap_to_push = dict(
                    fvAp=dict(
                        attributes=dict(
                            name=ap
                        ),
                        children=[epg_to_push]
                    ))

                binding_tree_to_push = dict(
                    fvTenant=dict(
                        attributes=dict(
                            name=tenant
                        ),
                        children=[ap_to_push]))

                if not children:
                    children.append(binding_tree_to_push)
                    continue

                tenant_existing = next((tenant_exist for tenant_exist in children
                                   if tenant_exist.get("fvTenant", {}).get("attributes", {}).get("name", None) == tenant), None)

                if tenant_existing is not None:
                    tenant_children = tenant_existing.get("fvTenant").get("children", [])
                    ap_existing = next((ap_exist for ap_exist in tenant_children
                                           if ap_exist.get("fvAp", {}).get("attributes", {}).get("name", None) == ap), None)

                    if ap_existing is not None:
                        fv_ap_children = ap_existing.get("fvAp").get("children", [])
                        epg_existing = next((epg_exist for epg_exist in fv_ap_children
                                           if epg_exist.get("fvAEPg", {}).get("attributes", {}).get("name", None) == epg), None)

                        if epg_existing is not None:
                            fv_epg_children = epg_existing.get("fvAEPg").get("children", [])
                            fv_epg_children.append(binding_to_push)
                        else:
                            fv_ap_children.append(epg_to_push)

                    else:
                        tenant_children.append(ap_to_push)

                else:
                    children.append(binding_tree_to_push)

        aci.path = 'api/mo/uni.json'
        aci.url = "{0}/{1}".format(aci.base_url, aci.path)
        aci.payload(
            aci_class="polUni",
            class_config=dict(),
            child_configs=children,

        )

        aci.get_diff(aci_class="polUni")

        aci.post_config()
        aci.exit_json()


if __name__ == "__main__":
    main()
