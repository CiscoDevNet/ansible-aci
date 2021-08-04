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
module: aci_l4l7_service_graph_template
short_description: Manage L4-L7 Service Graph Templates (vns:AbsGraph)
description:
- Manage L4-L7 Service Graph Templates on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  service_graph:
    description:
    - Name of Service Graph Template
    type: str
  ui_template_type:
    description:
    - UI Template Type
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg
'''

EXAMPLES = r'''
- name: Add a new L4-L7 Service Graph Template
  cisco.aci.aci_l4l7_service_graph_template:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: my_service_graph
    state: present
  delegate_to: localhost

- name: Delete a Service Graph Template
  cisco.aci.aci_l4l7_service_graph_template:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: my_service_graph
    state: absent
  delegate_to: localhost

- name: Query a Service Graph Template
  cisco.aci.aci_l4l7_service_graph_template:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: my_service_graph
    state: query
  register: query_result
  delegate_to: localhost

- name: Query all Service Graph Templates
  cisco.aci.aci_l4l7_service_graph_template:
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
        state=dict(type='str', default='present',
                   choices=['absent', 'present', 'query']),
        ui_template_type=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['tenant', 'service_graph']],
            ['state', 'present', ['tenant', 'service_graph']]
        ]
    )

    tenant = module.params.get('tenant')
    service_graph = module.params.get('service_graph')
    state = module.params.get('state')
    ui_template_type = module.params.get('ui_template_type')

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
        child_classes=['vnsAbsTermNodeProv', 'vnsAbsTermNodeCon']
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='vnsAbsGraph',
            class_config=dict(
                name=service_graph,
                uiTemplateType=ui_template_type
            ),
        )
        aci.get_diff(aci_class='vnsAbsGraph')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
