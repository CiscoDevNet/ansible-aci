#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloud_region 
short_description: Manage Cloud Providers Region (cloud:Region)
description:
- Mo doc not defined in techpub!!!
notes:
- More information about the internal APIC class B(cloud:Region) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Devarshi Shah (@devarshishah3)
version_added: '2.7'
options: 
  adminSt:
    description:
    - administrative state of the object or policy 
    choices: [ managed, unmanaged ] 
  annotation:
    description:
    - Mo doc not defined in techpub!!! 
  name:
    description:
    - object name 
    aliases: [ cloud_provider's_region ] 
  nameAlias:
    description:
    - Mo doc not defined in techpub!!! 
  cloud_provider_profile_vendor:
    description:
    - vendor of the controller 
    choices: [ aws ] 
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
        'adminSt': dict(type='str', choices=['managed', 'unmanaged'], ),
        'annotation': dict(type='str',),
        'name': dict(type='str', aliases=["cloud_provider's_region"]),
        'nameAlias': dict(type='str',),
        'cloud_provider_profile_vendor': dict(type='str', choices=['aws'], ),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),

    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', ['name', 'cloud_provider_profile_vendor', ]], 
            ['state', 'present', ['name', 'cloud_provider_profile_vendor', ]],
        ],
    )
    
    adminSt = module.params['adminSt']
    annotation = module.params['annotation']
    name = module.params['name']
    nameAlias = module.params['nameAlias']
    cloud_provider_profile_vendor = module.params['cloud_provider_profile_vendor']
    state = module.params['state']
    child_configs=[]
    

    aci = ACIModule(module)
    aci.construct_url(
        root_class={
            'aci_class': 'cloudProvP',
            'aci_rn': 'clouddomp/provp-{}'.format(cloud_provider_profile_vendor),
            'target_filter': 'eq(cloudProvP.vendor, "{}")'.format(cloud_provider_profile_vendor),
            'module_object': cloud_provider_profile_vendor
        }, 
        subclass_1={
            'aci_class': 'cloudRegion',
            'aci_rn': 'region-{}'.format(name),
            'target_filter': 'eq(cloudRegion.name, "{}")'.format(name),
            'module_object': name
        }, 
        
        child_classes=[]
        
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudRegion',
            class_config={ 
                'adminSt': adminSt,
                'annotation': annotation,
                'name': name,
                'nameAlias': nameAlias,
            },
            child_configs=child_configs
           
        )

        aci.get_diff(aci_class='cloudRegion')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()