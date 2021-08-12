#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloud_epg 
short_description: Manage Cloud EPg (cloud:EPg)
description:
- Manage Cloud EPg on Cisco ACI fabrics
notes:
- More information about the internal APIC class B(cloud:EPg) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- nkatarmal-crest(@nirav.katarmal)
- Cindy Zhao (@cizhao)
options:
  descr:
    description:
    - Description of the Cloud EPg. 
  name:
    description:
    - The name of the Cloud EPg.
    aliases: [ cloud_epg ]
  tenant:
    description:
    - Then name of the Tenant.
  cloud_application_profile:
    description:
    - The name of the cloud application profile.
  vrf:
    description:
    - The name of the VRF.
    type: str
    aliases: [ context, vrf_name ]
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
        'descr': dict(type='str',),
        'name': dict(type='str', aliases=['cloud_epg']),
        'tenant': dict(type='str',),
        'cloud_application_profile': dict(type='str',),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),
        'vrf': dict(type='str', aliases=['context', 'vrf_name']),
    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', ['name', 'tenant', 'cloud_application_profile', ]], 
            ['state', 'present', ['name', 'tenant', 'cloud_application_profile', ]],
        ],
    )
    
    descr = module.params['descr']
    name = module.params['name']
    tenant = module.params['tenant']
    cloud_application_profile = module.params['cloud_application_profile']
    state = module.params['state']
    child_configs=[]
    relation_cloudrscloudepgctx = module.params['vrf']

    if relation_cloudrscloudepgctx:
        child_configs.append({'cloudRsCloudEPgCtx': {'attributes': {'tnFvCtxName': relation_cloudrscloudepgctx}}})

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
            'aci_rn': 'cloudapp-{}'.format(cloud_application_profile),
            'target_filter': 'eq(cloudApp.name, "{}")'.format(cloud_application_profile),
            'module_object': cloud_application_profile
        }, 
        subclass_2={
            'aci_class': 'cloudEPg',
            'aci_rn': 'cloudepg-{}'.format(name),
            'target_filter': 'eq(cloudEPg.name, "{}")'.format(name),
            'module_object': name
        }, 
        child_classes=['cloudRsCloudEPgCtx']
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudEPg',
            class_config={ 
                'descr': descr,
                'name': name,
            },
            child_configs=child_configs
        )

        aci.get_diff(aci_class='cloudEPg')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()