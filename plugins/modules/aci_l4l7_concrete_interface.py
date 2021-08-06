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
module: aci_l4l7_concrete_interface
short_description: Manage L4-L7 Concrete Interfaces (vns:CIf)
description:
- Manage L4-L7 Concrete Interfaces.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  device:
    description:
    - Name of an existing logical device
    type: str
  concrete_device:
    description:
    - Name of an existing concrete device
    type: str
  concrete_interface:
    description:
    - Name of the concrete interface
    type: str
  pod_id:
    description:
    - Pod ID the concrete interface exists on
    type: int
  node_id:
    description:
    - Node ID the concrete interface exists on
    - For Ports and Port-channels this is a single node-id
    - For vPCs this is a hyphen separated pair of node-ids, e.g. "201-202"
    type: str
  path_ep:
    description:
    - Path to the physical interface
    - For single ports, this is the port name, e.g. "eth1/15"
    - For Port-channels and vPCs, this is the Interface Policy Group name
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
- module: aci_l4l7_device
- module: aci_l4l7_concrete_device
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes, B(vnsCIf) and B(vnsRsCIfPathAtt)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
'''

EXAMPLES = r'''
- name: Add a new concrete interface on a single port
  cisco.aci.aci_l4l7_concrete_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    concrete_device: my_concrete_device
    concrete_interface: my_concrete_interface
    pod_id: 1
    node_id: 201
    path_ep: eth1/16
    state: present
  delegate_to: localhost

- name: Add a new concrete interface on a vPC
  cisco.aci.aci_l4l7_concrete_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    concrete_device: my_concrete_device
    concrete_interface: my_concrete_interface
    pod_id: 1
    node_id: 201-202
    path_ep: my_vpc_ipg
    state: present
  delegate_to: localhost

- name: Delete a concrete interface
  cisco.aci.aci_l4l7_concrete_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    concrete_device: my_concrete_device
    concrete_interface: my_concrete_interface
    pod_id: 1
    node_id: 201-202
    path_ep: my_vpc_ipg
    state: absent
  delegate_to: localhost

- name: Query a concrete interface
  cisco.aci.aci_l4l7_service_graph_template:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    concrete_device: my_concrete_device
    concrete_interface: my_concrete_interface
    pod_id: 1
    node_id: 201-202
    path_ep: my_vpc_ipg
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all concrete interfaces
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
        device=dict(type='str'),
        concrete_device=dict(type='str'),
        state=dict(type='str', default='present',
                   choices=['absent', 'present', 'query']),
        concrete_interface=dict(type='str'),
        pod_id=dict(type='int'),
        node_id=dict(type='str'),
        path_ep=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['tenant', 'device', 'concrete_device',
                                 'concrete_interface']],
            ['state', 'present', ['tenant', 'device', 'concrete_device',
                                  'concrete_interface', 'pod_id', 'node_id',
                                  'path_ep']]
        ]
    )

    tenant = module.params.get('tenant')
    state = module.params.get('state')
    device = module.params.get('device')
    concrete_device = module.params.get('concrete_device')
    concrete_interface = module.params.get('concrete_interface')
    pod_id = module.params.get('pod_id')
    node_id = module.params.get('node_id')
    path_ep = module.params.get('path_ep')

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant},
        ),
        subclass_1=dict(
            aci_class='vnsLDevVip',
            aci_rn='lDevVip-{0}'.format(device),
            module_object=device,
            target_filter={'name': device},
        ),
        subclass_2=dict(
            aci_class='vnsCDev',
            aci_rn='cDev-{0}'.format(concrete_device),
            module_object=concrete_device,
            target_filter={'name': concrete_device},
        ),
        subclass_3=dict(
            aci_class='vnsCIf',
            aci_rn='cIf-[{0}]'.format(concrete_interface),
            module_object=concrete_interface,
            target_filter={'name': concrete_interface},
        ),
        child_classes=['vnsRsCIfPathAtt']
    )

    aci.get_existing()

    if state == 'present':
        if '-' in node_id:
            path_type = 'protpaths'
        else:
            path_type = 'paths'

        path_dn = ('topology/pod-{0}/{1}-{2}/pathep-[{3}]'.format(pod_id,
                                                                  path_type,
                                                                  node_id,
                                                                  path_ep))
        aci.payload(
            aci_class='vnsCIf',
            class_config=dict(
                name=concrete_interface
            ),
            child_configs=[
                dict(
                    vnsRsCIfPathAtt=dict(
                        attributes=dict(
                            tDn=path_dn
                        ),
                    ),
                ),
            ],
        )
        aci.get_diff(aci_class='vnsCIf')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()