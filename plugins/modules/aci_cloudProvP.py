#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloudProvP 
short_description: Manage Cloud Provider Profile (cloud:ProvP)
description:
- Mo doc not defined in techpub!!!
notes:
- More information about the internal APIC class B(cloud:ProvP) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Devarshi Shah (@devarshishah3)
version_added: '2.7'
options: 
  annotation:
    description:
    - Mo doc not defined in techpub!!! 
  vendor:
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
        'annotation': dict(type='str',),
        'vendor': dict(type='str', choices=['aws'], ),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),

    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', ['vendor', ]], 
            ['state', 'present', ['vendor', ]],
        ],
    )
    
    annotation = module.params['annotation']
    vendor = module.params['vendor']
    state = module.params['state']
    child_configs=[]
    

    aci = ACIModule(module)
    aci.construct_url(
        root_class={
            'aci_class': 'cloudProvP',
            'aci_rn': 'clouddomp/provp-{}'.format(vendor),
            'target_filter': 'eq(cloudProvP.vendor, "{}")'.format(vendor),
            'module_object': vendor
        }, 
        
        child_classes=[]
        
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudProvP',
            class_config={ 
                'annotation': annotation,
                'vendor': vendor,
            },
            child_configs=child_configs
           
        )

        aci.get_diff(aci_class='cloudProvP')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()