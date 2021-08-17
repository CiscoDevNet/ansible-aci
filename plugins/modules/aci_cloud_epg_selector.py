#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloudEPSelector 
short_description: Manage Cloud Endpoint Selector (cloud:EPSelector)
description:
- Mo doc not defined in techpub!!!
notes:
- More information about the internal APIC class B(cloud:EPSelector) from
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
  matchExpression:
    description:
    - Mo doc not defined in techpub!!! 
  name:
    description:
    - object name 
    aliases: [ cloud_endpoint_selector ] 
  nameAlias:
    description:
    - Mo doc not defined in techpub!!! 
  ownerKey:
    description:
    - key for enabling clients to own their data 
  ownerTag:
    description:
    - tag for enabling clients to add their own data 
  tenant:
    description:
    - tenant name 
  cloud_application_container:
    description:
    - object name 
  cloud_epg:
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
        'descr': dict(type='str',),
        'matchExpression': dict(type='str',),
        'name': dict(type='str', aliases=['cloud_endpoint_selector']),
        'nameAlias': dict(type='str',),
        'ownerKey': dict(type='str',),
        'ownerTag': dict(type='str',),
        'tenant': dict(type='str',),
        'cloud_application_container': dict(type='str',),
        'cloud_epg': dict(type='str',),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),

    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', ['name', 'tenant', 'cloud_application_container', 'cloud_epg', ]], 
            ['state', 'present', ['name', 'tenant', 'cloud_application_container', 'cloud_epg', ]],
        ],
    )
    
    annotation = module.params['annotation']
    descr = module.params['descr']
    matchExpression = module.params['matchExpression']
    name = module.params['name']
    nameAlias = module.params['nameAlias']
    ownerKey = module.params['ownerKey']
    ownerTag = module.params['ownerTag']
    tenant = module.params['tenant']
    cloud_application_container = module.params['cloud_application_container']
    cloud_epg = module.params['cloud_epg']
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
            'aci_class': 'cloudApp',
            'aci_rn': 'cloudapp-{}'.format(cloud_application_container),
            'target_filter': 'eq(cloudApp.name, "{}")'.format(cloud_application_container),
            'module_object': cloud_application_container
        }, 
        subclass_2={
            'aci_class': 'cloudEPg',
            'aci_rn': 'cloudepg-{}'.format(cloud_epg),
            'target_filter': 'eq(cloudEPg.name, "{}")'.format(cloud_epg),
            'module_object': cloud_epg
        }, 
        subclass_3={
            'aci_class': 'cloudEPSelector',
            'aci_rn': 'epselector-{}'.format(name),
            'target_filter': 'eq(cloudEPSelector.name, "{}")'.format(name),
            'module_object': name
        }, 
        
        child_classes=[]
        
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudEPSelector',
            class_config={ 
                'annotation': annotation,
                'descr': descr,
                'matchExpression': matchExpression,
                'name': name,
                'nameAlias': nameAlias,
                'ownerKey': ownerKey,
                'ownerTag': ownerTag,
            },
            child_configs=child_configs
           
        )

        aci.get_diff(aci_class='cloudEPSelector')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()