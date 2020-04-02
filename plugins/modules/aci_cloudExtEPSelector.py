#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloudExtEPSelector 
short_description: Manage Cloud Endpoint Selector for External EPgs (cloud:ExtEPSelector)
description:
- Mo doc not defined in techpub!!!
notes:
- More information about the internal APIC class B(cloud:ExtEPSelector) from
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
  isShared:
    description:
    - Mo doc not defined in techpub!!! 
    choices: [ no, yes ] 
  nameAlias:
    description:
    - Mo doc not defined in techpub!!! 
  ownerKey:
    description:
    - key for enabling clients to own their data 
  ownerTag:
    description:
    - tag for enabling clients to add their own data 
  subnet:
    description:
    - Mo doc not defined in techpub!!! 
  tenant:
    description:
    - tenant name 
  cloud_application_container:
    description:
    - object name 
  cloud_external_epg:
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
        'isShared': dict(type='str', choices=['no', 'yes'], ),
        'nameAlias': dict(type='str',),
        'ownerKey': dict(type='str',),
        'ownerTag': dict(type='str',),
        'subnet': dict(type='str',),
        'tenant': dict(type='str',),
        'cloud_application_container': dict(type='str',),
        'cloud_external_epg': dict(type='str',),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),

    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', ['subnet', 'tenant', 'cloud_application_container', 'cloud_external_epg', ]], 
            ['state', 'present', ['subnet', 'tenant', 'cloud_application_container', 'cloud_external_epg', ]],
        ],
    )
    
    annotation = module.params['annotation']
    descr = module.params['descr']
    isShared = module.params['isShared']
    nameAlias = module.params['nameAlias']
    ownerKey = module.params['ownerKey']
    ownerTag = module.params['ownerTag']
    subnet = module.params['subnet']
    tenant = module.params['tenant']
    cloud_application_container = module.params['cloud_application_container']
    cloud_external_epg = module.params['cloud_external_epg']
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
            'aci_class': 'cloudExtEPg',
            'aci_rn': 'cloudextepg-{}'.format(cloud_external_epg),
            'target_filter': 'eq(cloudExtEPg.name, "{}")'.format(cloud_external_epg),
            'module_object': cloud_external_epg
        }, 
        subclass_3={
            'aci_class': 'cloudExtEPSelector',
            'aci_rn': 'extepselector-[{}]'.format(subnet),
            'target_filter': 'eq(cloudExtEPSelector.name, "{}")'.format(subnet),
            'module_object': subnet
        }, 
        
        child_classes=[]
        
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudExtEPSelector',
            class_config={ 
                'annotation': annotation,
                'descr': descr,
                'isShared': isShared,
                'nameAlias': nameAlias,
                'ownerKey': ownerKey,
                'ownerTag': ownerTag,
                'subnet': subnet,
            },
            child_configs=child_configs
           
        )

        aci.get_diff(aci_class='cloudExtEPSelector')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()