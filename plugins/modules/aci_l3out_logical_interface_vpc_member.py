#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Anvitha Jain(@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
---
module: aci_l3out_logical_interface_vpc_member
short_description: Manage Member Node objects (l3extMember:Member)
description:
- Manage Member Node objects (l3extMember:Member)
options:
  description:
    description:
    - The description for the logical interface VPC member.
    type: str
    aliases: [ descr ]
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
  logical_node:
    description:
    - Name of an existing logical node profile.
    type: str
  logical_interface:
    description:
    - Name of an existing logical interface.
    type: str
  path_dn:
    description:
    - DN of existing path endpoints for VPC policy group used to reach external L3 network.
    type: str
  side:
    description:
    - Provides the side of member.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
extends_documentation_fragment:
- cisco.aci.aci

notes:
- The C(tenant), C(l3out), C(logical_node), C(logical_interface), C(path_dn) and C(member) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_l3out) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l3out
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l3ext:Out).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Anvitha Jain(@anvitha-jain)
'''

EXAMPLES = r'''
- name: Create a VPC member
  cisco.aci.aci_l3out_logical_interface_vpc_member:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    l3out: l3out
    logical_node: nodeName
    logical_interface: interfaceName
    path_dn: topology/pod-1/protpaths-101-102/pathep-[policy_group_name]
    side: A
    state: present
  delegate_to: localhost

- name: Delete a VPC member
  cisco.aci.aci_l3out_logical_interface_vpc_member:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    l3out: l3out
    logical_node: nodeName
    logical_interface: interfaceName
    path_dn: topology/pod-1/protpaths-101-102/pathep-[policy_group_name]
    side: A
    state: absent
  delegate_to: localhost

- name: Query all VPC members
  cisco.aci.aci_l3out_logical_interface_vpc_member:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific VPC member under l3out
  cisco.aci.aci_l3out_logical_interface_vpc_member:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    l3out: l3out
    logical_node: nodeName
    logical_interface: interfaceName
    path_dn: topology/pod-1/protpaths-101-102/pathep-[policy_group_name]
    side: A
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
        tenant=dict(type='str', aliases=['tenant_name']),  # Not required for querying all objects
        l3out=dict(type='str', aliases=['l3out_name']),  # Not required for querying all objects
        logical_node=dict(type='str'),  # Not required for querying all objects
        logical_interface=dict(type='str'),
        path_dn=dict(type='str'),
        side=dict(type='str'),
        description=dict(type='str', aliases=['descr']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
        name_alias=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'present', ['side', 'path_dn', 'logical_interface', 'logical_node', 'l3out', 'tenant']],
            ['state', 'absent', ['side', 'path_dn', 'logical_interface', 'logical_node', 'l3out', 'tenant']],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get('tenant')
    l3out = module.params.get('l3out')
    logical_node = module.params.get('logical_node')
    logical_interface = module.params.get('logical_interface')
    path_dn = module.params.get('path_dn')
    side = module.params.get('side')
    description = module.params.get('description')
    state = module.params.get('state')
    name_alias = module.params.get('name_alias')

    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant},
        ),
        subclass_1=dict(
            aci_class='l3extOut',
            aci_rn='out-{0}'.format(l3out),
            module_object=l3out,
            target_filter={'name': l3out},
        ),
        subclass_2=dict(
            aci_class='l3extLNodeP',
            aci_rn='lnodep-{0}'.format(logical_node),
            module_object=logical_node,
            target_filter={'name': logical_node},
        ),
        subclass_3=dict(
            aci_class='l3extLIfP',
            aci_rn='lifp-{0}'.format(logical_interface),
            module_object=logical_interface,
            target_filter={'name': logical_interface},
        ),
        subclass_4=dict(
            aci_class='l3extRsPathL3OutAtt',
            aci_rn='rspathL3OutAtt-[{0}]'.format(path_dn),
            module_object=path_dn,
            target_filter={'name': path_dn},
        ),
        subclass_5=dict(
            aci_class='l3extMember',
            aci_rn='mem-{0}'.format(side),
            module_object=side,
            target_filter={'name': side},
        ),
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='l3extMember',
            class_config=dict(
                name=side,
                descr=description,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class='l3extMember')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
