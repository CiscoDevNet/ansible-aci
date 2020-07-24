#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloudCtxProfile 
short_description: Manage Cloud Context Profile (cloud:CtxProfile)
description:
- Mo doc not defined in techpub!!!
notes:
- More information about the internal APIC class B(cloud:CtxProfile) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Devarshi Shah (@devarshishah3)
version_added: '2.7'
options:
  descr:
    description:
    - configuration item description. 
    type: str
  name:
    description:
    - object name 
    type: str
    aliases: [ cloud_context_profile ] 
  nameAlias:
    description:
    - Mo doc not defined in techpub!!!
    type: str
  type:
    description:
    - component type 
    choices: [ regular, shadow ] 
  tenant:
    description:
    - tenant name
    type: str
  primary_cidr:
    description:
    - cidr block range of primary cidr
    type: str
  vrf:
    description:
    - name of vrf to be managed
    type: str
  region:
    description:
    - name of region to be managed
    type: str
  vpn_gateway:
    description:
    - whether vpn gateway router is enabled or not
    type: bool
  state: 
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    choices: [ absent, present, query ]
    default: present

extends_documentation_fragment: aci
'''

EXAMPLES = r'''
- name: Add a new aci cloud ctx profile
  aci_cloud_ctx_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: tenant_1
    name: cloud_ctx_profile
    vrf: VRF1
    region: us-west-1
    primary_cidr: '10.0.10.1/16'
    state: present
  delegate_to: localhost

- name: Remove an aci cloud ctx profile
  aci_cloud_ctx_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: tenant_1
    name: cloud_ctx_profile
    state: absent
  delegate_to: localhost

- name: Query aci cloud ctx profile
  aci_cloud_ctx_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    name: ctx_profile_1
    state: query
  delegate_to: localhost
'''

RETURN = r'''
'''

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
from ansible.module_utils.basic import AnsibleModule

def main():
    argument_spec = aci_argument_spec()
    argument_spec.update({ 
        'descr': dict(type='str',),
        'name': dict(type='str', aliases=['cloud_context_profile']),
        'nameAlias': dict(type='str',),
        'type': dict(type='str', choices=['regular', 'shadow'], ),
        'tenant': dict(type='str',),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),
        'primary_cidr': dict(type='str',),
        # FIXME: didn't find the flow_log in UI
        # 'flow_log': dict(type='str'),
        'vrf': dict(type='str'),
        'region': dict(type='str'),
        'vpn_gateway': dict(type='bool', default=False)
    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', ['name', 'tenant']], 
            ['state', 'present', ['name', 'tenant', 'vrf', 'region', 'primary_cidr']],
        ],
    )

    descr = module.params['descr']
    name = module.params['name']
    nameAlias = module.params['nameAlias']
    type = module.params['type']
    tenant = module.params['tenant']
    state = module.params['state']
    primary_cidr = module.params['primary_cidr']
    child_configs=[]

    vrf = module.params['vrf']
    region = module.params['region']
    vpn_gateway = module.params['vpn_gateway']
    if vrf:
        child_configs.append({'cloudRsToCtx': {'attributes': {'tnFvCtxName': vrf}}})
    if region:
        child_configs.append( 
          {
            'cloudRsCtxProfileToRegion': {
              'attributes': {
                'tDn': "uni/clouddomp/provp-aws/region-{}".format(region)
              }
            }
          }
        )
    if vpn_gateway:
        child_configs.append(
          {
            "cloudRouterP": {
              "attributes": {
                "name": "default"
                },
                "children": [{
                  "cloudIntNetworkP": {
                    "attributes": {
                      "name": "default"
                    }
                  }
                }]
            }
          }
        )
    child_configs.append(
      {
        'cloudCidr': {
          'attributes': {
            "addr": primary_cidr,
				    "primary": "yes"
          }
        }
      }
    )
    aci = ACIModule(module)
    aci.construct_url(
        root_class={
            'aci_class': 'fvTenant',
            'aci_rn': 'tn-{}'.format(tenant),
            'target_filter': 'eq(fvTenant.name, "{}")'.format(tenant),
            'module_object': tenant
        }, 
        subclass_1={
            'aci_class': 'cloudCtxProfile',
            'aci_rn': 'ctxprofile-{}'.format(name),
            'target_filter': 'eq(cloudCtxProfile.name, "{}")'.format(name),
            'module_object': name
        },
        
        child_classes=['cloudRsToCtx','cloudRsCtxProfileToRegion', 'cloudRouterP', 'cloudCidr']
        
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudCtxProfile',
            class_config={
                'descr': descr,
                'name': name,
                'nameAlias': nameAlias,
                'type': type,
            },
            child_configs=child_configs
        )

        aci.get_diff(aci_class='cloudCtxProfile')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()