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
module: aci_l3out_interface_secondary_ip
short_description: Manage Layer 3 Outside (L3Out) interface secondary IP addresses (l3ext:Ip).
description:
- Manage Layer 3 Outside (L3Out) interface secondary IP addresses (l3ext:Ip).
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l3out:
    description:
    - Name of an existing L3Out.
    type: str
    aliases: [ l3out_name ]
  node_profile:
    description:
    - Name of the node profile.
    type: str
    aliases: [ node_profile_name, logical_node ]
  interface_profile:
    description:
    - Name of the interface profile.
    type: str
    aliases: [ interface_profile_name, logical_interface ]
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
 side:
    description:
    - Provides the side for vPC member interfaces.
    type: str
    choices: [ A, B ]
  addr:
    description:
    - Secondary IP address.
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
- module: aci_l3out
- module: aci_l3out_logical_node_profile
- module: aci_l3out_logical_interface_profile
- module: aci_l3out_logical_interface
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l3ext:RsPathL3OutAtt)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Marcel Zehnder (@maercu)
'''

EXAMPLES = r'''
- name: Add a new secondary IP to a routed interface
  cisco.aci.aci_l3out_interface_secondary_ip:
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
    addr: 192.168.10.2/27
    state: present
  delegate_to: localhost

- name: Add a new secondary IP to a vPC member
  cisco.aci.aci_l3out_interface_secondary_ip:
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
    side: A
    addr: 192.168.10.2/27
    state: present
  delegate_to: localhost

- name: Delete a secondary IP
  cisco.aci.aci_l3out_interface_secondary_ip:
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
    addr: 192.168.10.2/27
    state: absent
  delegate_to: localhost

- name: Query a secondary IP
  cisco.aci.aci_l3out_interface_secondary_ip:
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
    addr: 192.168.10.2/27
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

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        tenant=dict(type='str', aliases=['tenant_name']),
        l3out=dict(type='str', aliases=['l3out_name']),
        node_profile=dict(type='str', aliases=[
                          'node_profile_name', 'logical_node']),
        interface_profile=dict(type='str', aliases=[
            'interface_profile_name', 'logical_interface']),
        state=dict(type='str', default='present',
                   choices=['absent', 'present', 'query']),
        pod_id=dict(type='str'),
        node_id=dict(type='str'),
        path_ep=dict(type='str'),
        side=dict(type='str', choices=['A', 'B']),
        addr=dict(type='str'),
        ipv6_dad=dict(type='str', default='enabled',
                      choices=['enabled', 'disabled'])
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[]
    )

    tenant = module.params.get('tenant')
    l3out = module.params.get('l3out')
    node_profile = module.params.get('node_profile')
    interface_profile = module.params.get('interface_profile')
    pod_id = module.params.get('pod_id')
    node_id = module.params.get('node_id')
    path_ep = module.params.get('path_ep')
    side = module.params.get('side')
    addr = module.params.get('addr')
    ipv6_dad = module.params.get('ipv6_dad')
    state = module.params.get('state')

    aci = ACIModule(module)

    path_type = 'paths'
    member = ''

    if node_id:
        if '-' in node_id:
            path_type = 'protpaths'
            member = 'mem-{0}/'.format(side)

    path_dn = ('topology/pod-{0}/{1}-{2}/pathep-[{3}]'.format(pod_id,
                                                              path_type,
                                                              node_id,
                                                              path_ep))

    aci.construct_url(
        root_class=dict(
            aci_class='l3extIp',
            aci_rn='tn-{0}/out-{1}/lnodep-{2}/lifp-{3}/rspathL3OutAtt-[{4}]/{5}addr-[{6}]'.format(
                tenant, l3out, node_profile, interface_profile, path_dn, member, addr),
            module_object=addr,
            target_filter={'addr': addr},
        )
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='l3extIp',
            class_config=dict(addr=addr, ipv6Dad=ipv6_dad)
        )

        aci.get_diff(aci_class='l3extIp')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
