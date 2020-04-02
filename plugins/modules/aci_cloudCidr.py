#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloudCidr 
short_description: Manage Cloud CIDR Pool (cloud:Cidr)
description:
- Mo doc not defined in techpub!!!
notes:
- More information about the internal APIC class B(cloud:Cidr) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Devarshi Shah (@devarshishah3)
version_added: '2.7'
options: 
  addr:
    description:
    - peer address 
  annotation:
    description:
    - Mo doc not defined in techpub!!! 
  descr:
    description:
    - configuration item description. 
  nameAlias:
    description:
    - Mo doc not defined in techpub!!! 
  ownerKey:
    description:
    - key for enabling clients to own their data 
  ownerTag:
    description:
    - tag for enabling clients to add their own data 
  primary:
    description:
    - Mo doc not defined in techpub!!! 
    choices: [ no, yes ] 
  tenant:
    description:
    - tenant name 
  cloud_context_profile:
    description:
    - object name 
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
        'addr': dict(type='str',),
        'annotation': dict(type='str',),
        'descr': dict(type='str',),
        'nameAlias': dict(type='str',),
        'ownerKey': dict(type='str',),
        'ownerTag': dict(type='str',),
        'primary': dict(type='str', choices=['no', 'yes'], ),
        'tenant': dict(type='str',),
        'cloud_context_profile': dict(type='str',),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),

    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', ['addr', 'tenant', 'cloud_context_profile', ]], 
            ['state', 'present', ['addr', 'tenant', 'cloud_context_profile', ]],
        ],
    )
    
    addr = module.params['addr']
    annotation = module.params['annotation']
    descr = module.params['descr']
    nameAlias = module.params['nameAlias']
    ownerKey = module.params['ownerKey']
    ownerTag = module.params['ownerTag']
    primary = module.params['primary']
    tenant = module.params['tenant']
    cloud_context_profile = module.params['cloud_context_profile']
    state = module.params['state']
    child_configs=[]
    

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
            'aci_rn': 'ctxprofile-{}'.format(cloud_context_profile),
            'target_filter': 'eq(cloudCtxProfile.name, "{}")'.format(cloud_context_profile),
            'module_object': cloud_context_profile
        }, 
        subclass_2={
            'aci_class': 'cloudCidr',
            'aci_rn': 'cidr-[{}]'.format(addr),
            'target_filter': 'eq(cloudCidr.addr, "{}")'.format(addr),
            'module_object': addr
        }, 
        
        child_classes=[]
        
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudCidr',
            class_config={ 
                'addr': addr,
                'annotation': annotation,
                'descr': descr,
                'nameAlias': nameAlias,
                'ownerKey': ownerKey,
                'ownerTag': ownerTag,
                'primary': primary,
            },
            child_configs=child_configs
           
        )

        aci.get_diff(aci_class='cloudCidr')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()