#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: aci_l4l7_service_graph_template_node
short_description: Manage L4-L7 Service Graph Templates Nodes (vns:AbsNode)
description:
- Manage Manage L4-L7 Service Graph Templates Nodes.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  service_graph:
    description:
    - Name of an existing Service Graph
    type: str
  node:
    description:
    - Name of the Service Graph Template Node
    type:str
  func_template_type:
    description:
    - Functional template type for the node
    type: str
    choices: [ FW_TRANS, FW_ROUTED, ADC_ONE_ARM, ADC_TWO_ARM, OTHER ]
  func_type:
    description:
    - Type of connection
    type: str
    choices: [ None, GoTo, GoThrough, L1, L2 ]
  device:
    description:
    - Name of an existing logical device
    type: str
  device_tenant:
    description:
    - Tenant the logical device exists under
    - Not required if logical device and node exist within the same tenant
    - Intended use case is when the device is in the C(common) tenant but the node is not
    type: str
  managed:
    description:
    - Is this device managed by the apic
    type: bool
  routing_mode:
    description:
    - Routing mode for the node
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

notes:
- The C(tenant) and C(service_graph) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_l4l7_service_graph_template_node) modules can be used for this.
seealso:
- module: aci_l4l7_service_graph_template
- module: aci_l4l7_device
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(vnsAbsNode)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
'''

EXAMPLES = r'''
- name: Add a new Service Graph Template Node
  cisco.aci.aci_l4l7_service_graph_template_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: test-graph
    node: test-node
    func_template_type: ADC_ONE_ARM
    func_type: GoTo
    device: test-device
    managed: no
    routing_mode: Redirect
    state: present
  delegate_to: localhost

- name: Delete a Service Graph Template Node
  cisco.aci.aci_l4l7_service_graph_template_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: test-graph
    node: test-node
    state: absent
  delegate_to: localhost

- name: Query a Service Graph Template Node
  cisco.aci.aci_l4l7_service_graph_template_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: test-graph
    node: test-node
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Service Graph Template Nodes
  cisco.aci.aci_l4l7_service_graph_template_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

'''

RETURN = r'''
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
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        tenant=dict(type='str', aliases=['tenant_name']),
        service_graph=dict(type='str'),
        node=dict(type='str'),
        state=dict(type='str', default='present',
                   choices=['absent', 'present', 'query']),
        func_template_type=dict(type='str', choices=['FW_TRANS',
                                                     'FW_ROUTED',
                                                     'ADC_ONE_ARM',
                                                     'ADC_TWO_ARM',
                                                     'OTHER']),
        func_type=dict(type='str', choices=['None',
                                            'GoTo',
                                            'GoThrough',
                                            'L1',
                                            'L2']),
        device=dict(type='str'),
        device_tenant=dict(type='str'),
        managed=dict(type='bool'),
        routing_mode=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['tenant', 'service_graph', 'node']],
            ['state', 'present', ['tenant', 'service_graph', 'node', 'device']]
        ]
    )

    tenant = module.params.get('tenant')
    service_graph = module.params.get('service_graph')
    node = module.params.get('node')
    state = module.params.get('state')
    func_template_type = module.params.get('func_template_type')
    func_type = module.params.get('func_type')
    device = module.params.get('device')
    device_tenant = module.params.get('device_tenant')
    managed = aci.boolean(module.params.get('managed'))
    routing_mode = module.params.get('routing_mode')

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant},
        ),
        subclass_1=dict(
            aci_class='vnsAbsGraph',
            aci_rn='AbsGraph-{0}'.format(service_graph),
            module_object=service_graph,
            target_filter={'name': service_graph},
        ),
        subclass_2=dict(
            aci_class='vnsAbsNode',
            aci_rn='AbsNode-{0}'.format(node),
            module_object=node,
            target_filter={'name': node},
        ),
        child_classes=['vnsRsNodeToLDev']
    )

    aci.get_existing()
    if not device_tenant:
        device_tenant = tenant
    dev_tdn = 'uni/tn-{0}/lDevVip-{1}'.format(device_tenant, device)

    if state == 'present':
        aci.payload(
            aci_class='vnsAbsNode',
            class_config=dict(
                name=node,
                funcTemplateType=func_template_type,
                funcType=func_type,
                managed=managed,
                routingMode=routing_mode
            ),
            child_configs=[
                dict(
                    vnsRsNodeToLDev=dict(
                        attributes=dict(
                            tDn=dev_tdn
                        ),
                    ),
                ),
            ],
        )
        aci.get_diff(aci_class='vnsAbsNode')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
