#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l4l7_device_selection_if_context_to_redir_pol
short_description: Manage L4-L7 Device Selection Interface Context binding to Logical Interfaces (vns:RsLIfCtxToSvcRedirectPol)
description:
- Manage L4-L7 Device Selection Interface Context Binding to Policy Based Redirection Policy
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  contract:
    description:
    - Name of an existing contract
    type: str
    aliases: [ contract_name ]
  graph:
    description:
    - Name of an existing Service Graph Template
    type: str
    aliases: [ service_graph, service_graph_name ]
  node:
    description:
    - Name of an existing Service Graph Node
    type: str
    aliases: [ node_name ]
  context:
    description:
    - Name of the logical interface context
    type: str
  policy:
    description:
    - Name of an existing Policy Based Redirect Policy
    type: str
    aliases: [ redirect_policy ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci

notes:
- The C(tenant), C(contract), C(graph), C(node), C(context), C(Device) and C(interface) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.contract), M(cisco.aci.aci_l4l7_service_graph_template),
  M(cisco.aci.aci_l4l7_service_graph_template_node), M(cisco.aci.aci_l4l7_device_selection_if_context),
  and M(cisco.aci.aci_l4l7_policy_based_redirect) modules can be used for this.
seealso:
- module: aci_l4l7_device_selection_policy
- module: aci_l4l7_device_selection_if_context
- module: aci_l4l7_service_graph_template
- module: aci_l4l7_service_graph_template_node
- module: aci_contract
- module: aci_l4l7_policy_based_redirect
- name: APIC Management Information Model reference
  description: More information about the internal APIC class (vnsRsLIfCtxToSvcRedirectPol)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Bind a Policy Based Redirect Policy to an Interface Context
  cisco.aci.aci_l4l7_device_selection_if_context_to_redir_pol:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    contract: my_contract
    graph: my_graph
    node: my_node
    context: my_context
    policy: my_pbr_policy
    state: present
  delegate_to: localhost

- name: Remove a Policy Based Redirect Policy from an Interface Context
  cisco.aci.aci_l4l7_device_selection_if_context_to_redir_pol:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    contract: my_contract
    graph: my_graph
    node: my_node
    context: my_context
    policy: my_pbr_policy
    state: present
  delegate_to: localhost

- name: Query Policy Based Redirect Policy used on an Interface Context
  cisco.aci.aci_l4l7_device_selection_if_context_to_redir_pol:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    contract: my_contract
    graph: my_graph
    node: my_node
    context: my_context
    policy: my_pbr_policy
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        contract=dict(type="str", aliases=["contract_name"]),
        graph=dict(type="str", aliases=["service_graph", "service_graph_name"]),
        node=dict(type="str", aliases=["node_name"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        context=dict(type="str"),
        policy=dict(type="str", aliases=["redirect_policy"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "contract", "graph", "node", "context", "policy"]],
            ["state", "present", ["tenant", "contract", "graph", "node", "context", "policy"]],
        ],
    )

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    contract = module.params.get("contract")
    graph = module.params.get("graph")
    node = module.params.get("node")
    context = module.params.get("context")
    policy = module.params.get("policy")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="vnsLDevCtx",
            aci_rn="ldevCtx-c-{0}-g-{1}-n-{2}".format(contract, graph, node),
            module_object=("ldevCtx-c-{0}-g-{1}-n-{2}".format(contract, graph, node)),
            target_filter={"dn": "ldevCtx-c-{0}-g-{1}-n-{2}".format(contract, graph, node)},
        ),
        subclass_2=dict(
            aci_class="vnsLIfCtx",
            aci_rn="lIfCtx-c-{0}".format(context),
            module_object=context,
            target_filter={"connNameOrLbl": context},
        ),
        subclass_3=dict(
            aci_class="vnsRsLIfCtxToSvcRedirectPol",
            aci_rn="rsLIfCtxToSvcRedirectPol",
            module_object=("uni/tn-{0}/svcCont/svcRedirectPol-{1}".format(tenant, policy)),
            target_filter={"tDn": "uni/tn-{0}/svcCont/svcRedirectPol-{1}".format(tenant, policy)},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="vnsRsLIfCtxToSvcRedirectPol",
            class_config=dict(tDn=("uni/tn-{0}/svcCont/svcRedirectPol-{1}".format(tenant, policy))),
        )
        aci.get_diff(aci_class="vnsRsLIfCtxToSvcRedirectPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
