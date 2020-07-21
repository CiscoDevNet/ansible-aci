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
  annotation:
    description:
    - Mo doc not defined in techpub!!! 
  descr:
    description:
    - configuration item description. 
  name:
    description:
    - object name 
    aliases: [ cloud_context_profile ] 
  nameAlias:
    description:
    - Mo doc not defined in techpub!!! 
  ownerKey:
    description:
    - key for enabling clients to own their data 
  ownerTag:
    description:
    - tag for enabling clients to add their own data 
  type:
    description:
    - component type 
    choices: [ regular, shadow ] 
  tenant:
    description:
    - tenant name 
  state: 
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    choices: [ absent, present, query ]
    default: present 

extends_documentation_fragment: aci
'''

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
from ansible.module_utils.basic import AnsibleModule

def main():
    argument_spec = aci_argument_spec()
    argument_spec.update({ 
        'annotation': dict(type='str',),
        'descr': dict(type='str',),
        'name': dict(type='str', aliases=['cloud_context_profile']),
        'nameAlias': dict(type='str',),
        'ownerKey': dict(type='str',),
        'ownerTag': dict(type='str',),
        'type': dict(type='str', choices=['regular', 'shadow'], ),
        'tenant': dict(type='str',),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),
        'primary_cidr': dict(type='str',),
        'relation_cloud_rs_ctx_to_flow_log': dict(type='str'),
        'vrf': dict(type='str'),
        'region': dict(type='str'),

    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', ['name', 'tenant',]], 
            ['state', 'present', ['name', 'tenant', 'vrf', 'region', 'primary_cidr',]],
        ],
    )
    
    annotation = module.params['annotation']
    descr = module.params['descr']
    name = module.params['name']
    nameAlias = module.params['nameAlias']
    ownerKey = module.params['ownerKey']
    ownerTag = module.params['ownerTag']
    type = module.params['type']
    tenant = module.params['tenant']
    state = module.params['state']
    primary_cidr = module.params['primary_cidr']
    child_configs=[]
    
    relation_cloudrsctxtoflowlog = module.params['relation_cloud_rs_ctx_to_flow_log']
    relation_cloudrstoctx = module.params['vrf']
    relation_cloudrsctxprofiletoregion = module.params['region']
    if relation_cloudrsctxtoflowlog:
        child_configs.append({'cloudRsCtxToFlowLog': {'attributes': {'tnCloudAwsFlowLogPolName': relation_cloudrsctxtoflowlog}}})
    if relation_cloudrstoctx:
        child_configs.append({'cloudRsToCtx': {'attributes': {'tnFvCtxName': relation_cloudrstoctx}}})
    if relation_cloudrsctxprofiletoregion:
        child_configs.append( 
          {
            'cloudRsCtxProfileToRegion': {
              'attributes': {
                'tDn': "uni/clouddomp/provp-aws/region-{}".format(relation_cloudrsctxprofiletoregion)
              }
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
        
        child_classes=['cloudRsCtxToFlowLog','cloudRsToCtx','cloudRsCtxProfileToRegion', 'cloudCidr']
        
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudCtxProfile',
            class_config={ 
                'annotation': annotation,
                'descr': descr,
                'name': name,
                'nameAlias': nameAlias,
                'ownerKey': ownerKey,
                'ownerTag': ownerTag,
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