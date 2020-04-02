#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloudSubnet 
short_description: Manage Cloud Subnet (cloud:Subnet)
description:
- Mo doc not defined in techpub!!!
notes:
- More information about the internal APIC class B(cloud:Subnet) from
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
  ip:
    description:
    - ip address 
  nameAlias:
    description:
    - Mo doc not defined in techpub!!! 
  scope:
    description:
    - capability domain 
    choices: [ private, public, shared ] 
  usage:
    description:
    - usage of the port 
    choices: [ infra-router, user ] 
  tenant:
    description:
    - tenant name 
  cloud_context_profile:
    description:
    - object name 
  cloud_cidr_pool_addr:
    description:
    - peer address 
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
        'ip': dict(type='str',),
        'nameAlias': dict(type='str',),
        'scope': dict(type='str', choices=['private', 'public', 'shared'], ),
        'usage': dict(type='str', choices=['infra-router', 'user'], ),
        'tenant': dict(type='str',),
        'cloud_context_profile': dict(type='str',),
        'cloud_cidr_pool_addr': dict(type='str',),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),

        'relation_cloud_rs_zone_attach': dict(type='str'),


    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', ['ip', 'tenant', 'cloud_context_profile', 'cloud_cidr_pool_addr', ]], 
            ['state', 'present', ['ip', 'tenant', 'cloud_context_profile', 'cloud_cidr_pool_addr', ]],
        ],
    )
    
    annotation = module.params['annotation']
    descr = module.params['descr']
    ip = module.params['ip']
    nameAlias = module.params['nameAlias']
    scope = module.params['scope']
    usage = module.params['usage']
    tenant = module.params['tenant']
    cloud_context_profile = module.params['cloud_context_profile']
    cloud_cidr_pool_addr = module.params['cloud_cidr_pool_addr']
    state = module.params['state']
    child_configs=[]
    
    relation_cloudrszoneattach = module.params['relation_cloud_rs_zone_attach']
    if relation_cloudrszoneattach:
        child_configs.append({'cloudRsZoneAttach': {'attributes': {'tnCloudZoneName': relation_cloudrszoneattach}}})

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
            'aci_rn': 'cidr-[{}]'.format(cloud_cidr_pool_addr),
            'target_filter': 'eq(cloudCidr.addr, "{}")'.format(cloud_cidr_pool_addr),
            'module_object': cloud_cidr_pool_addr
        }, 
        subclass_3={
            'aci_class': 'cloudSubnet',
            'aci_rn': 'subnet-[{}]'.format(ip),
            'target_filter': 'eq(cloudSubnet.ip, "{}")'.format(ip),
            'module_object': ip
        }, 
        
        child_classes=['cloudRsZoneAttach']
        
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudSubnet',
            class_config={ 
                'annotation': annotation,
                'descr': descr,
                'ip': ip,
                'nameAlias': nameAlias,
                'scope': scope,
                'usage': usage,
            },
            child_configs=child_configs
           
        )

        aci.get_diff(aci_class='cloudSubnet')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()