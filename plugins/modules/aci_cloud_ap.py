#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, nkatarmal-crest (@nirav.katarmal)
# Copyright: (c) 2021, Cindy Zhao (@cizhao)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloudApp 
short_description: Manage Cloud Application container (cloud:App)
description:
- Manage Cloud Application Profile (AP) objects on Cisco ACI fabrics
notes:
- More information about the internal APIC class B(cloud:App) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- nkatarmal-crest (@nirav.katarmal)
- Cindy Zhao (@cizhao)
options: 
  descr:
    description:
    - Description for the cloud AP. 
  name:
    description:
    - The name of the cloud application profile.
    aliases: [ cloud_application_container ] 
  tenant:
    description:
    - The name of an existing tenant.
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
    argument_spec.update(
        descr=dict(type='str',),
        name=dict(type='str', aliases=['cloud_application_container']),
        tenant=dict(type='str',),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', ['name', 'tenant', ]], 
            ['state', 'present', ['name', 'tenant', ]],
        ],
    )
    
    descr = module.params['descr']
    name = module.params['name']
    tenant = module.params['tenant']
    state = module.params['state']
    child_configs=[]
    

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{}'.format(tenant),
            target_filter={'name': tenant},
            module_object=tenant,
        ), 
        subclass_1=dict(
            aci_class='cloudApp',
            aci_rn='cloudapp-{}'.format(name),
            target_filter={'name': name},
            module_object=name,
        ), 
        child_classes=[]
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudApp',
            class_config=dict(
                descr=descr,
                name=name,
            ),
            child_configs=child_configs
        )

        aci.get_diff(aci_class='cloudApp')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()