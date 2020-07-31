#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloudZone 
short_description: Manage Cloud Availability Zone (cloud:Zone)
description:
- Mo doc not defined in techpub!!!
notes:
- More information about the internal APIC class B(cloud:Zone) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Devarshi Shah (@devarshishah3)
version_added: '2.7'
options: 
  annotation:
    description:
    - Mo doc not defined in techpub!!! 
  name:
    description:
    - object name 
    aliases: [ cloud_availability_zone ] 
  nameAlias:
    description:
    - Mo doc not defined in techpub!!! 
  cloud_provider_profile_vendor:
    description:
    - vendor of the controller 
    choices: [ aws ] 
  cloud_providers_region:
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
        'annotation': dict(type='str',),
        'name': dict(type='str', aliases=['cloud_availability_zone']),
        'nameAlias': dict(type='str',),
        'cloud_provider_profile_vendor': dict(type='str', choices=['aws'], ),
        'cloud_providers_region': dict(type='str',),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),

    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', ['name', 'cloud_provider_profile_vendor', 'cloud_providers_region', ]], 
            ['state', 'present', ['name', 'cloud_provider_profile_vendor', 'cloud_providers_region', ]],
        ],
    )
    
    annotation = module.params['annotation']
    name = module.params['name']
    nameAlias = module.params['nameAlias']
    cloud_provider_profile_vendor = module.params['cloud_provider_profile_vendor']
    cloud_providers_region = module.params['cloud_providers_region']
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
            'aci_rn': 'region-{}'.format(cloud_providers_region),
            'target_filter': 'eq(cloudRegion.name, "{}")'.format(cloud_providers_region),
            'module_object': cloud_providers_region
        }, 
        subclass_2={
            'aci_class': 'cloudZone',
            'aci_rn': 'zone-{}'.format(name),
            'target_filter': 'eq(cloudZone.name, "{}")'.format(name),
            'module_object': name
        }, 
        
        child_classes=[]
        
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudZone',
            class_config={ 
                'annotation': annotation,
                'name': name,
                'nameAlias': nameAlias,
            },
            child_configs=child_configs
           
        )

        aci.get_diff(aci_class='cloudZone')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()