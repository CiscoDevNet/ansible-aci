#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Bruno Calogero <brunocalogero@hotmail.com>
# Copyright: (c) 2022, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function, annotations

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "certified",
}

DOCUMENTATION = r"""
---
module: aci_bulk_static_binding_to_epg
short_description: Bind static paths to EPGs (fv:RsPathAtt)
description:
- Bind static paths to EPGs on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of the tenant.
    - Module level EPG attributes are mutually exclusive with the EPGs list.
    type: str
    aliases: [ tenant_name ]
  ap:
    description:
    - The name of the application profile.
    - Module level EPG attributes are mutually exclusive with the EPGs list.
    type: str
    aliases: [ app_profile, app_profile_name ]
  epg:
    description:
    - The name of the end point group.
    - Module level EPG attributes are mutually exclusive with the EPGs list.
    type: str
    aliases: [ epg_name ]
  description:
    description:
    - Description for the static path to EPG binding.
    - Module level EPG attributes are mutually exclusive with the EPGs list.
    type: str
    aliases: [ descr ]
  encap_id:
    description:
    - The encapsulation ID associating the C(epg) with the interface path.
    - This acts as the secondary C(encap_id) when using micro-segmentation.
    - Accepted values are any valid encap ID for specified encap, currently ranges between C(1) and C(4096).
    - Module level EPG attributes are mutually exclusive with the EPGs list.
    type: int
    aliases: [ vlan, vlan_id ]
  primary_encap_id:
    description:
    - Determines the primary encapsulation ID associating the C(epg)
      with the interface path when using micro-segmentation.
    - Accepted values are any valid encap ID for specified encap, currently ranges between C(1) and C(4096) and C(unknown).
    - C(unknown) is the default value and using C(unknown) disables the Micro-Segmentation.
    - Module level EPG attributes are mutually exclusive with the EPGs list.
    type: str
    aliases: [ primary_vlan, primary_vlan_id ]
  deploy_immediacy:
    description:
    - The Deployment Immediacy of Static EPG on PC, VPC or Interface.
    - The APIC defaults to C(lazy) when unset during creation.
    - Module level EPG attributes are mutually exclusive with the EPGs list.
    type: str
    choices: [ immediate, lazy ]
  interface_mode:
    description:
    - Determines how layer 2 tags will be read from and added to frames.
    - Values C(802.1p) and C(native) are identical.
    - Values C(access) and C(untagged) are identical.
    - Values C(regular), C(tagged) and C(trunk) are identical.
    - The APIC defaults to C(trunk) when unset during creation.
    - Module level EPG attributes are mutually exclusive with the EPGs list.
    type: str
    choices: [ 802.1p, access, native, regular, tagged, trunk, untagged ]
    aliases: [ interface_mode_name, mode ]
  interface_type:
    description:
    - The type of interface for the static EPG deployment.
    - Module level EPG attributes are mutually exclusive with the EPGs list.
    type: str
    choices: [ fex, port_channel, switch_port, vpc, fex_port_channel, fex_vpc ]
    default: switch_port
  epgs:
    description:
    - List of EPG configurations with elements in the form of a dictionary.
    - Module level EPG attributes are mutually exclusive with this EPGs list.
    - Attributes defined in this epgs list will be overridden by the path level attributes if provided.
    - The Path Level attributes encap_id and primary_encap_id are ignored if the epgs list is used.
    type: list
    elements: dict
    suboptions:
      tenant:
        description:
        - Name of the tenant.
        type: str
        aliases: [ tenant_name ]
      ap:
        description:
        - The name of the application profile.
        type: str
        aliases: [ app_profile, app_profile_name ]
      epg:
        description:
        - The name of the endpoint group.
        type: str
        aliases: [ epg_name ]
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
      interface_type:
        description:
        - The type of interface for the static EPG deployment.
        - Different interface types are not supported at this level.
        type: str
        choices: [ fex, port_channel, switch_port, vpc, fex_port_channel, fex_vpc ]
        default: switch_port
  interface_configs:
    description:
    - List of interface configurations, elements in the form of a dictionary.
    - Module level attributes will be overridden by the path level attributes.
    - The Path Level attributes encap_id and primary_encap_id are ignored if the epgs list is used.
    type: list
    elements: dict
    suboptions:
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
        - This attribute will be ignored if the epgs list is used.
        type: int
        aliases: [ vlan, vlan_id ]
      primary_encap_id:
        description:
        - Determines the primary encapsulation ID associating the C(epg)
          with the interface path when using micro-segmentation.
        - Accepted values are any valid encap ID for specified encap, currently ranges between C(1) and C(4096) and C(unknown).
        - C(unknown) is the default value and using C(unknown) disables the Micro-Segmentation.
        - This attribute will be ignored if the epgs list is used.
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
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
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
- Bruno Calogero (@brunocalogero)
- Marcel Zehnder (@maercu)
- Sabari Jaganathan (@sajagana)
- Andreas Graber (@andreasgraber)
"""

EXAMPLES = r"""
- name: Create list of interfaces using module level attributes
  cisco.aci.aci_bulk_static_binding_to_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: accessport-code-cert
    ap: accessport_code_app
    epg: accessport_epg1
    encap_id: 221
    interface_mode: trunk
    deploy_immediacy: lazy
    description: "Module level attributes used to create interfaces"
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
    state: present
  delegate_to: localhost

- name: Create/Update list of interfaces using path level attributes
  cisco.aci.aci_bulk_static_binding_to_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: accessport-code-cert
    ap: accessport_code_app
    epg: accessport_epg1
    interface_configs:
      - interface: 1/7
        leafs: 101
        pod: 1
        encap_id: 221
        interface_mode: trunk
        deploy_immediacy: lazy
        description: "Path level attributes used to create/update interfaces"
      - interface: 1/7
        leafs: 107
        pod: 7
        encap_id: 221
        interface_mode: trunk
        deploy_immediacy: lazy
        description: "Path level attributes used to create/update interfaces"
      - interface: 1/8
        leafs: 108
        pod: 8
        encap_id: 108
        interface_mode: trunk
        deploy_immediacy: lazy
        description: "Path level attributes used to create/update interfaces"
    state: present
  delegate_to: localhost

- name: Query all interfaces of an EPG
  cisco.aci.aci_bulk_static_binding_to_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: accessport-code-cert
    ap: accessport_code_app
    epg: accessport_epg1
    state: query
  delegate_to: localhost

- name: Query all interfaces
  cisco.aci.aci_bulk_static_binding_to_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Remove list of interfaces
  cisco.aci.aci_bulk_static_binding_to_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: accessport-code-cert
    ap: accessport_code_app
    epg: accessport_epg1
    encap_id: 221
    interface_mode: trunk
    deploy_immediacy: lazy
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

- name: Create list of interfaces using epgs list
  cisco.aci.aci_bulk_static_binding_to_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    epgs:
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
    state: present
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
  type: dict
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
  description: The assembled configuration from the user-provided parameters. Dict for single EPG, List for multiple EPGs.
  returned: info
  type: raw
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
import json
from typing import Optional
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    aci_annotation_spec,
)

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


def aci_epg_spec():
    return dict(
        tenant=dict(type="str", aliases=["tenant_name"]),
        ap=dict(type="str", aliases=["app_profile", "app_profile_name"]),
        epg=dict(type="str", aliases=["epg_name"]),
        description=dict(type="str", aliases=["descr"]),
        encap_id=dict(type="int", aliases=["vlan", "vlan_id"]),
        primary_encap_id=dict(type="str", aliases=["primary_vlan", "primary_vlan_id"]),
        deploy_immediacy=dict(type="str", choices=["immediate", "lazy"]),
        interface_mode=dict(
            type="str",
            choices=[
                "802.1p",
                "access",
                "native",
                "regular",
                "tagged",
                "trunk",
                "untagged",
            ],
            aliases=["interface_mode_name", "mode"],
        ),
        interface_type=dict(
            type="str",
            default="switch_port",
            choices=[
                "fex",
                "port_channel",
                "switch_port",
                "vpc",
                "fex_port_channel",
                "fex_vpc",
            ],
        ),
    )


def validate_bindings(
    interface_configs: Optional[list[dict]],
    aci: ACIModule,
    module_interface_type: str,
    epg_dn: str,
    existing_epgs: list[dict],
) -> dict[str, dict]:
    static_paths_dn = [
        f"{epg_dn}/rspathAtt-[{validate_static_path(aci, interface_config, module_interface_type)}]" for interface_config in interface_configs or []
    ]
    existing_bindings_object = {}
    for epg in existing_epgs:
        epg_children = epg.get("fvAEPg", {}).get("children", [])
        for binding in epg_children:
            t_dn = binding.get("fvRsPathAtt", {}).get("attributes", {}).get("tDn")
            static_path_dn = f"{epg_dn}/rspathAtt-[{t_dn}]"
            if static_path_dn in static_paths_dn:
                existing_bindings_object[static_path_dn] = binding
    return existing_bindings_object


def validate_static_path(aci: ACIModule, interface_config: dict, module_interface_type: str = None) -> str:
    pod_id = interface_config.get("pod_id")
    interface = interface_config.get("interface")
    extpaths = interface_config.get("extpaths")
    interface_type = interface_config.get("interface_type") or module_interface_type or "switch_port"
    if interface_type in ["fex", "fex_vpc", "fex_port_channel"] and extpaths is None:
        aci.fail_json(msg="extpaths is required when interface_type is: {0}".format(interface_type))
    leafs = validate_leafs(aci, interface_config.get("leafs"), interface_type)
    extpaths = validate_ext_paths(
        aci=aci,
        extpaths_config=interface_config.get("extpaths"),
        interface_type=interface_type,
    )

    static_path = INTERFACE_TYPE_MAPPING[interface_type].format(pod_id=pod_id, leafs=leafs, extpaths=extpaths, interface=interface)
    return static_path


def get_existing_epg_based(
    aci: ACIModule,
    ap: Optional[str],
    epg: Optional[str],
    interface_configs: Optional[list[dict]],
    module_interface_type: str,
    tenant: Optional[str],
) -> dict:
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter=dict(name=tenant),
        ),
        subclass_1=dict(
            aci_class="fvAp",
            aci_rn="ap-{0}".format(ap),
            module_object=ap,
            target_filter=dict(name=ap),
        ),
        subclass_2=dict(
            aci_class="fvAEPg",
            aci_rn="epg-{0}".format(epg),
            module_object=epg,
            target_filter=dict(name=epg),
        ),
        child_classes=["fvRsPathAtt"],
    )
    aci.get_existing()
    if interface_configs:
        # This Function is validating the existing Bindings and get back a helper dict in order to easy access the existing bindings
        return validate_bindings(
            interface_configs=interface_configs,
            aci=aci,
            module_interface_type=module_interface_type,
            epg_dn=f"uni/tn-{tenant}/ap-{ap}/epg-{epg}",
            existing_epgs=aci.existing,
        )
    else:
        return dict()


def get_existing_epgs_based(
    aci: ACIModule,
    epgs: list[dict],
    interface_configs: Optional[list[dict]],
) -> dict:
    # Setting the Batch Size to 20 Interfaces, which could give max 81'880 bindings back which is still fine
    BATCH_SIZE = 20

    # Getting interface_types of the list of epgs and remove duplicates
    interface_types = list(set([epg.get("interface_type", "switch_port") for epg in epgs]))

    if len(interface_types) > 1:
        aci.fail_json(msg=f"Different interface types are not supported on epgs level! Got {interface_types}")

    epg_dict_existing_filtered = validate_epgs(aci, epgs)

    static_paths = []
    if interface_configs:
        for interface_config in interface_configs:
            static_paths.append(
                validate_static_path(
                    aci=aci,
                    interface_config=interface_config,
                    module_interface_type=interface_types[0],
                )
            )

    existing_bindings = []
    uri = "/api/class/fvRsPathAtt.json?rsp-prop-include=config-only"
    if not aci.suppress_previous:
        if len(static_paths) == 0:
            existing_bindings = get_objects_from_aci(aci=aci, uri=uri)
        else:
            index = 0
            while index < len(static_paths):
                batch = static_paths[index : index + BATCH_SIZE]
                joined_string = ",".join([f'eq(fvRsPathAtt.tDn,"{path}")' for path in batch])
                filter_string = f"query-target-filter=or({joined_string})"

                existing_bindings.extend(get_objects_from_aci(aci=aci, uri=f"{uri}&{filter_string}"))
                index += BATCH_SIZE

    existing_binding_objects = dict()
    for binding in existing_bindings:
        binding_attributes = binding["fvRsPathAtt"].get("attributes")
        binding_dn = binding_attributes.get("dn")
        epg_dn = binding_dn.split("/rspathAtt-")[0]
        epg_existing = epg_dict_existing_filtered.get(epg_dn)
        if epg_existing:
            epg_children = epg_existing.get("fvAEPg").setdefault("children", [])
            existing_binding_objects[binding_dn] = binding
            # Remove dn of Path attributes as the dn is given on the epg parent, which reflects the normal aci behaviour
            binding["fvRsPathAtt"]["attributes"].pop("dn")
            epg_children.append(binding)
        else:
            # Binding is not related to a Queried EPG
            continue
    aci.existing = list(epg_dict_existing_filtered.values())
    return existing_binding_objects


def validate_epgs(aci, epgs) -> dict:
    # This Function is checking if the EPGs are present in the Fabric and get back a helper dict for easy accessing
    # the EPG Objects later on.
    epg_list_existing = get_objects_from_aci(aci=aci, uri="/api/class/fvAEPg.json?rsp-prop-include=config-only")
    epg_dict_existing = {epg.get("fvAEPg", {}).get("attributes", {}).get("dn"): epg for epg in epg_list_existing}

    epg_dict_existing_filtered = dict()
    for epg in epgs:
        dn = f"uni/tn-{epg.get('tenant')}/ap-{epg.get('ap')}/epg-{epg.get('epg')}"
        epg_existing = epg_dict_existing.get(dn)
        if epg_existing:
            epg_dict_existing_filtered[dn] = epg_existing
        else:
            aci.fail_json(msg=f"The EPG with DN {dn} is not present in the Fabric. Can't proceed!")
    return epg_dict_existing_filtered


def get_objects_from_aci(aci: ACIModule, uri: str):
    response, info = aci.api_call(
        method="GET",
        url=f"{aci.base_url}{uri}",
        data=None,
        return_response=True,
    )
    if info.get("status") != 200:
        try:
            # APIC error
            aci.response_json(info["body"])
            aci.fail_json(msg="APIC Error {code}: {text}".format_map(aci.error))
        except KeyError:
            # Connection error
            aci.fail_json(msg="Connection failed for {url}. {msg}".format_map(info))
    try:
        response_data = json.loads(response.read())
    except AttributeError:
        response_data = json.loads(info.get("body"))

    return response_data["imdata"]


def should_post_binding(binding_config: dict, existing_binding: dict, state: str) -> bool:
    should_push = False
    if state == "present" and existing_binding is None:
        should_push = True
    elif state == "present" and existing_binding is not None:
        existing_attributes = existing_binding.get("fvRsPathAtt", {}).get("attributes", {})
        new_attributes = binding_config.get("fvRsPathAtt", {}).get("attributes", {})
        for key, value in new_attributes.items():
            if existing_attributes.get(key, None) != value:
                should_push = True
    elif state == "absent" and existing_binding is not None:
        should_push = True
    return should_push


def validate_ext_paths(aci: ACIModule, extpaths_config: Optional[list], interface_type: str) -> Optional[str]:
    if extpaths_config is not None:
        # Process extpaths, and support dash-delimited extpaths
        extpaths = []
        for extpath in extpaths_config:
            # Users are likely to use integers for extpaths IDs, which would raise an exception when using the join method
            extpaths.extend(str(extpath).split("-"))
        if len(extpaths) == 1:
            if interface_type == "fex_vpc":
                aci.fail_json(msg='A interface_type of "fex_vpc" requires 2 extpaths')
            extpaths = extpaths[0]
        elif len(extpaths) == 2:
            if interface_type != "fex_vpc":
                aci.fail_json(msg='The interface_types "fex" and "fex_port_channel" do not support using multiple extpaths for a single binding')
            extpaths = "-".join(extpaths)
        else:
            aci.fail_json(msg='The "extpaths" parameter must not have more than 2 entries')

        return extpaths
    return None


def validate_leafs(aci: ACIModule, leafs_config: list, interface_type: str) -> str:
    # Process leafs, and support dash-delimited leafs
    leafs = []
    for leaf in leafs_config:
        # Users are likely to use integers for leaf IDs, which would raise an exception when using the join method
        leafs.extend(str(leaf).split("-"))
    if len(leafs) == 1:
        if interface_type in ["vpc", "fex_vpc"]:
            aci.fail_json(msg='An interface_type of "vpc" or "fex_vpc" requires 2 leafs')
        leafs = leafs[0]
    elif len(leafs) == 2:
        if interface_type not in ["vpc", "fex_vpc"]:
            aci.fail_json(msg='The interface_types "switch_port", "port_channel", and "fex" do not support using multiple leafs for a single binding')
        leafs = "-".join(leafs)
    else:
        aci.fail_json(msg='The "leafs" parameter must not have more than 2 entries')
    return leafs


def validate_primary_encap_id(aci: ACIModule, primary_encap_id: str) -> str:
    if primary_encap_id is not None:
        try:
            primary_encap_id = int(primary_encap_id)
            if primary_encap_id in range(1, 4097):
                primary_encap_id = "vlan-{0}".format(primary_encap_id)
            else:
                aci.fail_json(msg="Valid VLAN assignments are from 1 to 4096 or unknown.")
        except ValueError as e:
            if isinstance(primary_encap_id, str) and primary_encap_id != "unknown":
                aci.fail_json(msg="Valid VLAN assignments are from 1 to 4096 or unknown. %s" % e)
    return primary_encap_id


def merge_binding_change_to_existing_config_dict(
    config_children: list[dict],
    tenant: str,
    ap: str,
    epg: str,
    binding_tree_config: dict,
    ap_config: dict,
    epg_config: dict,
):
    tenant_existing = next(
        (tenant_exist for tenant_exist in config_children if tenant_exist.get("fvTenant", {}).get("attributes", {}).get("name", None) == tenant),
        None,
    )
    if tenant_existing is not None:
        tenant_children = tenant_existing.get("fvTenant").get("children")
        ap_existing = next(
            (ap_exist for ap_exist in tenant_children if ap_exist.get("fvAp", {}).get("attributes", {}).get("name", None) == ap),
            None,
        )

        if ap_existing is not None:
            fv_ap_children = ap_existing.get("fvAp").get("children")
            epg_existing = next(
                (epg_exist for epg_exist in fv_ap_children if epg_exist.get("fvAEPg", {}).get("attributes", {}).get("name", None) == epg),
                None,
            )

            if epg_existing is None:
                fv_ap_children.append(epg_config)
        else:
            tenant_children.append(ap_config)

    else:
        config_children.append(binding_tree_config)


def get_epgs_exit_values(
    aci: ACIModule,
    changed: bool,
    check_mode: bool,
    epgs: list[dict],
    interface_configs: Optional[list[dict]],
):
    result = aci.result
    result["proposed"] = aci.proposed
    result["previous"] = aci.existing
    result["sent"] = aci.config
    result["mo"] = aci.config
    result["status"] = aci.status
    result["url"] = aci.url
    result["response"] = aci.response
    result["method"] = aci.method
    result["filter_string"] = aci.filter_string
    result["changed"] = changed
    if aci.httpapi_logs is not None:
        result["httpapi_logs"] = aci.httpapi_logs

    if check_mode is True:
        result["current"] = aci.existing
        return

    if aci.suppress_verification:
        if changed or aci.suppress_previous:
            result["current_verified"] = False
            result["current"] = aci.proposed
        else:
            # existing already equals the previous
            result["current_verified"] = True
    elif changed is True:
        get_existing_epgs_based(
            aci=aci,
            epgs=epgs,
            interface_configs=interface_configs,
        )
        result["current"] = aci.existing
    elif changed is False:
        result["current"] = result["previous"]


def validate_encap_id(aci: ACIModule, encap_id: int):
    if encap_id is not None:
        if encap_id not in range(1, 4097):
            aci.fail_json(msg="Valid VLAN assignments are from 1 to 4096")
        encap_id = "vlan-{0}".format(encap_id)
    return encap_id


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_epg_spec())
    argument_spec.update(
        epgs=dict(type="list", elements="dict", options=aci_epg_spec()),
        interface_configs=dict(
            type="list",
            elements="dict",
            options=dict(
                description=dict(type="str", aliases=["descr"]),
                encap_id=dict(type="int", aliases=["vlan", "vlan_id"]),
                primary_encap_id=dict(type="str", aliases=["primary_vlan", "primary_vlan_id"]),
                deploy_immediacy=dict(type="str", choices=["immediate", "lazy"]),
                interface_mode=dict(
                    type="str",
                    choices=[
                        "802.1p",
                        "access",
                        "native",
                        "regular",
                        "tagged",
                        "trunk",
                        "untagged",
                    ],
                    aliases=["interface_mode_name", "mode"],
                ),
                interface_type=dict(
                    type="str",
                    choices=[
                        "fex",
                        "port_channel",
                        "switch_port",
                        "vpc",
                        "fex_port_channel",
                        "fex_vpc",
                    ],
                ),
                pod_id=dict(type="int", required=True, aliases=["pod", "pod_number"]),
                leafs=dict(
                    type="list",
                    elements="str",
                    required=True,
                    aliases=["leaves", "nodes", "paths", "switches"],
                ),
                interface=dict(type="str", required=True),
                extpaths=dict(type="list", elements="str"),
            ),
        ),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("tenant", "epgs"),
            ("ap", "epgs"),
            ("epg", "epgs"),
            ("encap_id", "epgs"),
            ("primary_encap_id", "epgs"),
            ("interface_mode", "epgs"),
            ("interface_type", "epgs"),
            ("deploy_immediacy", "epgs"),
            ("description", "epgs"),
        ],
        required_if=[
            ["state", "absent", ["interface_configs"]],
            ["state", "present", ["interface_configs"]],
        ],
    )

    module_tenant = module.params.get("tenant")
    module_ap = module.params.get("ap")
    module_epg = module.params.get("epg")
    epgs = module.params.get("epgs")
    module_description = module.params.get("description")
    module_encap_id = module.params.get("encap_id")
    module_primary_encap_id = module.params.get("primary_encap_id")
    module_deploy_immediacy = module.params.get("deploy_immediacy")
    module_interface_mode = module.params.get("interface_mode")
    module_interface_type = module.params.get("interface_type")
    interface_configs = module.params.get("interface_configs")
    state = module.params.get("state")
    annotation = module.params.get("annotation")

    aci = ACIModule(module)

    if state in ["absent", "present"] and not module_epg and not epgs:
        aci.fail_json(msg="Either 'epg' or 'epgs' must be provided when state is '%s'." % state)

    config_children = []
    config = dict(polUni=dict(attributes=dict(), children=config_children))

    # Ensure Objects are created to avoid Warnings in the IDE
    static_bindings = []
    existing_binding_objects = {}

    if module_epg or (state == "query" and not epgs):
        # Case single EPG provided or a query without multiple EPG
        existing_binding_objects = get_existing_epg_based(
            aci=aci,
            tenant=module_tenant,
            ap=module_ap,
            epg=module_epg,
            interface_configs=interface_configs,
            module_interface_type=module_interface_type,
        )
        # Transform single EPG into a list of one dictionary in order to reuse the same domain logic as for multiple EPG.
        static_bindings = [
            {
                "tenant": module_tenant,
                "ap": module_ap,
                "epg": module_epg,
                "description": module_description,
                "encap_id": module_encap_id,
                "primary_encap_id": module_primary_encap_id,
                "deploy_immediacy": module_deploy_immediacy,
                "interface_mode": module_interface_mode,
                "interface_type": module_interface_type,
            }
        ]
    elif epgs:
        # Case multiple EPG provided
        existing_binding_objects = get_existing_epgs_based(
            aci=aci,
            epgs=epgs,
            interface_configs=interface_configs,
        )
        static_bindings = epgs
        aci.proposed = []  # proposed is a List in case of multiple EPG provided

    if state == "present" or state == "absent":
        for binding in static_bindings:
            tenant_inner = binding.get("tenant")
            ap_inner = binding.get("ap")
            epg_inner = binding.get("epg")

            if tenant_inner is None or ap_inner is None or epg_inner is None:
                aci.fail_json(msg=f"Tenant:{tenant_inner} AP:{ap_inner} EPG: {epg_inner} needs to be provided together!")

            module_description_inner = binding.get("description")
            module_encap_id_inner = binding.get("encap_id")
            module_primary_encap_id_inner = binding.get("primary_encap_id")
            module_deploy_immediacy_inner = binding.get("deploy_immediacy")
            module_interface_mode_inner = binding.get("interface_mode")
            module_interface_type_inner = binding.get("interface_type")

            # List for the Static Bindings, this list will be used for the aci.proposed and aci.config part
            epg_children_config = list()
            epg_config = dict(fvAEPg=dict(attributes=dict(name=epg_inner), children=epg_children_config))
            ap_config = dict(fvAp=dict(attributes=dict(name=ap_inner), children=[epg_config]))
            binding_tree_config = dict(fvTenant=dict(attributes=dict(name=tenant_inner), children=[ap_config]))

            if epgs:
                # Ensure Proposed gets the dn attribute and the Config dict not. Both uses the same children List in
                # order to get the Binding Changes
                aci.proposed.append(
                    dict(
                        fvAEPg=dict(
                            attributes=dict(
                                dn=f"uni/tn-{tenant_inner}/ap-{ap_inner}/epg-{epg_inner}",
                                name=epg_inner,
                            ),
                            children=epg_children_config,
                        )
                    )
                )

            for interface_config in interface_configs:
                pod_id = interface_config.get("pod_id")
                interface = interface_config.get("interface")
                extpaths = interface_config.get("extpaths")

                description = interface_config.get("description") or module_description_inner
                deploy_immediacy = interface_config.get("deploy_immediacy") or module_deploy_immediacy_inner
                interface_type = interface_config.get("interface_type") or module_interface_type_inner or "switch_port"
                encap_id = interface_config.get("encap_id") or module_encap_id_inner
                primary_encap_id = interface_config.get("primary_encap_id") or module_primary_encap_id_inner

                interface_mode = interface_config.get("interface_mode") or module_interface_mode_inner

                leafs = validate_leafs(aci=aci, leafs_config=interface_config.get("leafs"), interface_type=interface_type)

                extpaths = validate_ext_paths(aci=aci, extpaths_config=extpaths, interface_type=interface_type)

                encap_id = validate_encap_id(aci=aci, encap_id=encap_id)

                primary_encap_id = validate_primary_encap_id(aci=aci, primary_encap_id=primary_encap_id)

                static_path = INTERFACE_TYPE_MAPPING[interface_type].format(pod_id=pod_id, leafs=leafs, extpaths=extpaths, interface=interface)

                interface_mode = INTERFACE_MODE_MAPPING.get(interface_mode)

                interface_status = INTERFACE_STATUS_MAPPING.get(state)

                existing_binding = existing_binding_objects.get(f"uni/tn-{tenant_inner}/ap-{ap_inner}/epg-{epg_inner}/rspathAtt-[{static_path}]")

                attributes = dict(
                    descr=description,
                    encap=encap_id,
                    primaryEncap=primary_encap_id,
                    instrImedcy=deploy_immediacy,
                    mode=interface_mode,
                    tDn=static_path,
                    annotation=annotation,
                    status=interface_status,
                )
                # Remove None values
                attributes = {k: v for k, v in attributes.items() if v is not None}
                binding_config = dict(fvRsPathAtt=dict(attributes=attributes))

                if (
                    should_post_binding(
                        binding_config=binding_config,
                        existing_binding=existing_binding,
                        state=state,
                    )
                    is True
                ):
                    epg_config.get("fvAEPg", {}).get("children").append(binding_config)
                    merge_binding_change_to_existing_config_dict(
                        config_children=config_children,
                        tenant=tenant_inner,
                        ap=ap_inner,
                        epg=epg_inner,
                        ap_config=ap_config,
                        epg_config=epg_config,
                        binding_tree_config=binding_tree_config,
                    )

        if module_epg:
            aci.payload(
                aci_class="fvAEPg",
                class_config=dict(),
                child_configs=epg_config.get("fvAEPg", {}).get("children", []),
            )
            aci.get_diff(aci_class="fvAEPg")
            aci.post_config()
        else:
            aci.path = "api/node/mo/uni.json"
            aci.url = "{0}/{1}".format(aci.base_url, aci.path)
            aci.method = "POST"
            changed = False
            if config_children:
                aci.config = config
                changed = True
                if module.check_mode is False:
                    aci.api_call("POST", aci.url, json.dumps(aci.config))
            get_epgs_exit_values(
                aci=aci,
                changed=changed,
                check_mode=module.check_mode,
                epgs=epgs,
                interface_configs=interface_configs,
            )
            module.exit_json(**aci.result)

    aci.exit_json()


if __name__ == "__main__":
    main()
