#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloudBgpAsP 
short_description: Manage Autonomous System Profile (cloud:BgpAsP)
description:
- Mo doc not defined in techpub!!!
notes:
- More information about the internal APIC class B(cloud:BgpAsP) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Devarshi Shah (@devarshishah3)
version_added: '2.7'
options: 
  annotation:
    description:
    - Mo doc not defined in techpub!!! 
  asn:
    description:
    - autonomous system number 
  descr:
    description:
    - configuration item description. 
  name:
    description:
    - object name 
    aliases: [ autonomous_system_profile ] 
  nameAlias:
    description:
    - Mo doc not defined in techpub!!! 
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
        'asn': dict(type='str',),
        'descr': dict(type='str',),
        'name': dict(type='str', aliases=['autonomous_system_profile']),
        'nameAlias': dict(type='str',),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),

    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', []], 
            ['state', 'present', []],
        ],
    )
    
    annotation = module.params['annotation']
    asn = module.params['asn']
    descr = module.params['descr']
    name = module.params['name']
    nameAlias = module.params['nameAlias']
    state = module.params['state']
    child_configs=[]
    

    aci = ACIModule(module)
    aci.construct_url(
        root_class={
            'aci_class': 'cloudBgpAsP',
            'aci_rn': 'clouddomp/as'.format(),
            'target_filter': '',
            'module_object': None
        }, 
        
        child_classes=[]
        
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudBgpAsP',
            class_config={ 
                'annotation': annotation,
                'asn': asn,
                'descr': descr,
                'name': name,
                'nameAlias': nameAlias,
            },
            child_configs=child_configs
           
        )

        aci.get_diff(aci_class='cloudBgpAsP')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()