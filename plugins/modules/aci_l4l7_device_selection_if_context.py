#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l4l7_device_selection_if_context
short_description: Manage L4-L7 Device Selection Policy Logical Interface Contexts (vns:LIfCtx)
description:
- Manage L4-L7 Device Selection Policy Logical Interface Contexts
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  contract:
    description:
    - The name of an existing contract.
    type: str
    aliases: [ contract_name ]
  graph:
    description:
    - The name of an existing Service Graph Template.
    type: str
    aliases: [ service_graph, service_graph_name ]
  node:
    description:
    - The name of an existing Service Graph Node.
    type: str
    aliases: [ node_name ]
  context:
    description:
    - The name of the logical interface context.
    type: str
  l3_dest:
    description:
    - Whether the context is a Layer3 destination.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
  permit_log:
    description:
    - Whether to log permitted traffic.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  bridge_domain:
    description:
    - The Bridge Domain to bind to the Context.
    type: str
    aliases: [ bd, bd_name ]
  bridge_domain_tenant:
    description:
    - The tenant the Bridge Domain resides in.
    - Omit this variable if both context and Bridge Domain are in the same tenant.
    - Intended use case is for when the Bridge Domain is in the common tenant, but the context is not.
    type: str
    aliases: [ bd_tenant ]
  logical_device:
    description:
    - The Logical Device to bind the context to.
    type: str
  logical_interface:
    description:
    - The Logical Interface to bind the context to.
    type: str
  redirect_policy:
    description:
    - The Redirect Policy to bind the context to.
    type: str
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
- The I(tenant), I(graph), I(contract) and I(node) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l4l7_service_graph_template), M(cisco.aci.aci_contract)
  and M(cisco.aci.aci_l4l7_service_graph_template_node) modules can be used for this.
seealso:
- module: aci_l3out
- module: aci_l3out_logical_node_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC class, B(vns:LIfCtx)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new interface context
  cisco.aci.aci_l4l7_device_selection_if_context:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    contract: my_contract
    graph: my_graph
    node: my_node
    context: provider
    state: present
  delegate_to: localhost

- name: Delete an interface context
  cisco.aci.aci_l4l7_device_selection_if_context:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    contract: my_contract
    graph: my_graph
    node: my_node
    context: provider
    state: absent
  delegate_to: localhost

- name: Query an interface context
  cisco.aci.aci_l4l7_device_selection_if_context:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    contract: my_contract
    graph: my_graph
    node: my_node
    context: consumer
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all interface contexts
  cisco.aci.aci_l4l7_device_selection_if_context:
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
        tenant=dict(type="str", aliases=["tenant_name"]),
        contract=dict(type="str", aliases=["contract_name"]),
        graph=dict(type="str", aliases=["service_graph", "service_graph_name"]),
        node=dict(type="str", aliases=["node_name"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        context=dict(type="str"),
        l3_dest=dict(type="bool"),
        permit_log=dict(type="bool"),
        bridge_domain=dict(type="str", aliases=["bd", "bd_name"]),
        bridge_domain_tenant=dict(type="str", aliases=["bd_tenant"]),
        logical_device=dict(type="str"),
        logical_interface=dict(type="str"),
        redirect_policy=dict(type="str"),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "contract", "graph", "node", "context"]],
            ["state", "present", ["tenant", "contract", "graph", "node", "context"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    contract = module.params.get("contract")
    graph = module.params.get("graph")
    node = module.params.get("node")
    context = module.params.get("context")
    l3_dest = aci.boolean(module.params.get("l3_dest"))
    permit_log = aci.boolean(module.params.get("permit_log"))
    bridge_domain = module.params.get("bridge_domain")
    bridge_domain_tenant = module.params.get("bridge_domain_tenant")
    logical_device = module.params.get("logical_device")
    logical_interface = module.params.get("logical_interface")
    redirect_policy = module.params.get("redirect_policy")

    ldev_ctx_rn = "ldevCtx-c-{0}-g-{1}-n-{2}".format(contract, graph, node) if (contract, graph, node) != (None, None, None) else None

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="vnsLDevCtx",
            aci_rn=ldev_ctx_rn,
            module_object=ldev_ctx_rn,
            target_filter={"dn": ldev_ctx_rn},
        ),
        subclass_2=dict(
            aci_class="vnsLIfCtx",
            aci_rn="lIfCtx-c-{0}".format(context),
            module_object=context,
            target_filter={"connNameOrLbl": context},
        ),
        child_classes=["vnsRsLIfCtxToBD", "vnsRsLIfCtxToLIf", "vnsRsLIfCtxToSvcRedirectPol"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if bridge_domain is not None:
            if bridge_domain_tenant is None:
                bridge_domain_tenant = tenant
            bd_tdn = "uni/tn-{0}/BD-{1}".format(bridge_domain_tenant, bridge_domain)
            child_configs.append({"vnsRsLIfCtxToBD": {"attributes": {"tDn": bd_tdn}}})
        else:
            bd_tdn = None
        if logical_interface is not None:
            log_intf_tdn = "uni/tn-{0}/lDevVip-{1}/lIf-{2}".format(tenant, logical_device, logical_interface)
            child_configs.append({"vnsRsLIfCtxToLIf": {"attributes": {"tDn": log_intf_tdn}}})
        else:
            log_intf_tdn = None
        if redirect_policy is not None:
            redir_pol_tdn = "uni/tn-{0}/svcCont/svcRedirectPol-{1}".format(tenant, redirect_policy)
            child_configs.append({"vnsRsLIfCtxToSvcRedirectPol": {"attributes": {"tDn": redir_pol_tdn}}})
        else:
            redir_pol_tdn = None
        # Validate if existing and remove child objects when do not match provided configuration
        if isinstance(aci.existing, list) and len(aci.existing) > 0:
            for child in aci.existing[0].get("vnsLIfCtx", {}).get("children", {}):
                if child.get("vnsRsLIfCtxToBD") and child.get("vnsRsLIfCtxToBD").get("attributes").get("tDn") != bd_tdn:
                    # Appending to child_config list not possible because of APIC Error 103: child (Rn) of class vnsRsLIfCtxToBD is already attached.
                    # A seperate delete request to dn of the vnsRsLIfCtxToBD is needed to remove the object prior to adding to child_configs.
                    # child_configs.append(
                    #     {
                    #         "vnsRsLIfCtxToBD": {
                    #             "attributes": {
                    #                 "dn": child.get("vnsRsLIfCtxToBD").get("attributes").get("dn"),
                    #                 "status": "deleted",
                    #             }
                    #         }
                    #     }
                    # )
                    aci.delete_config_request(
                        "/api/mo/uni/tn-{0}/ldevCtx-c-{1}-g-{2}-n-{3}/lIfCtx-c-{4}/rsLIfCtxToBD.json".format(tenant, contract, graph, node, context)
                    )
                elif child.get("vnsRsLIfCtxToLIf") and child.get("vnsRsLIfCtxToLIf").get("attributes").get("tDn") != log_intf_tdn:
                    child_configs.append(
                        {
                            "vnsRsLIfCtxToLIf": {
                                "attributes": {
                                    "dn": child.get("vnsRsLIfCtxToLIf").get("attributes").get("dn"),
                                    "status": "deleted",
                                }
                            }
                        }
                    )
                elif child.get("vnsRsLIfCtxToSvcRedirectPol") and child.get("vnsRsLIfCtxToSvcRedirectPol").get("attributes").get("tDn") != redir_pol_tdn:
                    child_configs.append(
                        {
                            "vnsRsLIfCtxToSvcRedirectPol": {
                                "attributes": {
                                    "dn": child.get("vnsRsLIfCtxToSvcRedirectPol").get("attributes").get("dn"),
                                    "status": "deleted",
                                }
                            }
                        }
                    )
        aci.payload(
            aci_class="vnsLIfCtx",
            class_config=dict(connNameOrLbl=context, l3Dest=l3_dest, permitLog=permit_log),
            child_configs=child_configs,
        )
        aci.get_diff(aci_class="vnsLIfCtx")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()