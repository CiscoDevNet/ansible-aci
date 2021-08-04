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
module: aci_l3out_logical_interface_profile
short_description: Manage Layer 3 Outside (L3Out) logical interface profiles (l3ext:LIfP)
description:
- Manage L3Out interface profiles on Cisco ACI fabrics.
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
    aliases: [ name, interface_profile_name, logical_interface ]
  nd_policy:
    description:
    - Name of the neighbor discovery interface policy.
    type: str
  egress_dpp_policy:
    description:
    - Name of the egress data plane policing policy.
    type: str
  ingress_dpp_policy:
    description:
    - Name of the ingress data plane policing policy.
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
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Marcel Zehnder (@maercu)
'''

EXAMPLES = r'''
- name: Add a new interface profile
  cisco.aci.aci_l3out_logical_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    state: present
  delegate_to: localhost

- name: Delete an interface profile
  cisco.aci.aci_l3out_logical_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    state: absent
  delegate_to: localhost

- name: Query an interface profile
  cisco.aci.aci_l3out_logical_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all interface profiles
  cisco.aci.aci_l3out_logical_interface_profile:
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
        l3out=dict(type='str', aliases=['l3out_name']),
        node_profile=dict(type='str', aliases=[
                          'node_profile_name', 'logical_node']),
        interface_profile=dict(type='str', aliases=[
            'name', 'interface_profile_name', 'logical_interface']),
        nd_policy=dict(type='str', default=''),
        egress_dpp_policy=dict(type='str', default=''),
        ingress_dpp_policy=dict(type='str', default=''),
        state=dict(type='str', default='present',
                   choices=['absent', 'present', 'query'])
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['tenant', 'l3out',
                                 'node_profile', 'interface_profile']],
            ['state', 'present', ['tenant', 'l3out',
                                  'node_profile', 'interface_profile']]
        ]
    )

    tenant = module.params.get('tenant')
    l3out = module.params.get('l3out')
    node_profile = module.params.get('node_profile')
    interface_profile = module.params.get('interface_profile')
    nd_policy = module.params.get('nd_policy')
    egress_dpp_policy = module.params.get('egress_dpp_policy')
    ingress_dpp_policy = module.params.get('ingress_dpp_policy')
    state = module.params.get('state')

    aci = ACIModule(module)

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
            aci_rn='lnodep-{0}'.format(node_profile),
            module_object=node_profile,
            target_filter={'name': node_profile},
        ),
        subclass_3=dict(
            aci_class='l3extLIfP',
            aci_rn='lifp-[{0}]'.format(interface_profile),
            module_object=interface_profile,
            target_filter={'name': interface_profile},
        ),
        child_classes=['l3extRsNdIfPol',
                       'l3extRsIngressQosDppPol',
                       'l3extRsEgressQosDppPol']
    )

    aci.get_existing()

    if state == 'present':
        child_configs = [
            dict(l3extRsNdIfPol=dict(attributes=dict(tnNdIfPolName=nd_policy))),
            dict(l3extRsIngressQosDppPol=dict(
                attributes=dict(tnQosDppPolName=ingress_dpp_policy))),
            dict(l3extRsEgressQosDppPol=dict(
                attributes=dict(tnQosDppPolName=egress_dpp_policy)))
        ]
        aci.payload(
            aci_class='l3extLIfP',
            class_config=dict(name=interface_profile),
            child_configs=child_configs
        )

        aci.get_diff(aci_class='l3extLIfP')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
