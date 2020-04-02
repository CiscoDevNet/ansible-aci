#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloudAwsProvider 
short_description: Manage Cloud AWS Provider (cloud:AwsProvider)
description:
- Mo doc not defined in techpub!!!
notes:
- More information about the internal APIC class B(cloud:AwsProvider) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Devarshi Shah (@devarshishah3)
version_added: '2.7'
options: 
  accessKeyId:
    description:
    - Mo doc not defined in techpub!!! 
  accountId:
    description:
    - Mo doc not defined in techpub!!! 
  annotation:
    description:
    - Mo doc not defined in techpub!!! 
  descr:
    description:
    - configuration item description. 
  email:
    description:
    - email address of the local user 
  httpProxy:
    description:
    - Mo doc not defined in techpub!!! 
  isAccountInOrg:
    description:
    - Mo doc not defined in techpub!!! 
    choices: [ no, yes ] 
  isTrusted:
    description:
    - Mo doc not defined in techpub!!! 
    choices: [ no, yes ] 
  name:
    description:
    - object name 
    aliases: [ cloud_aws_provider ] 
  nameAlias:
    description:
    - Mo doc not defined in techpub!!! 
  ownerKey:
    description:
    - key for enabling clients to own their data 
  ownerTag:
    description:
    - tag for enabling clients to add their own data 
  providerId:
    description:
    - Mo doc not defined in techpub!!! 
  region:
    description:
    - Mo doc not defined in techpub!!! 
  secretAccessKey:
    description:
    - Mo doc not defined in techpub!!! 
  tenant:
    description:
    - tenant name 
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
        'accessKeyId': dict(type='str',),
        'accountId': dict(type='str',),
        'annotation': dict(type='str',),
        'descr': dict(type='str',),
        'email': dict(type='str',),
        'httpProxy': dict(type='str',),
        'isAccountInOrg': dict(type='str', choices=['no', 'yes'], ),
        'isTrusted': dict(type='str', choices=['no', 'yes'], ),
        'name': dict(type='str', aliases=['cloud_aws_provider']),
        'nameAlias': dict(type='str',),
        'ownerKey': dict(type='str',),
        'ownerTag': dict(type='str',),
        'providerId': dict(type='str',),
        'region': dict(type='str',),
        'secretAccessKey': dict(type='str',),
        'tenant': dict(type='str',),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),

    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', ['tenant', ]], 
            ['state', 'present', ['tenant', ]],
        ],
    )
    
    accessKeyId = module.params['accessKeyId']
    accountId = module.params['accountId']
    annotation = module.params['annotation']
    descr = module.params['descr']
    email = module.params['email']
    httpProxy = module.params['httpProxy']
    isAccountInOrg = module.params['isAccountInOrg']
    isTrusted = module.params['isTrusted']
    name = module.params['name']
    nameAlias = module.params['nameAlias']
    ownerKey = module.params['ownerKey']
    ownerTag = module.params['ownerTag']
    providerId = module.params['providerId']
    region = module.params['region']
    secretAccessKey = module.params['secretAccessKey']
    tenant = module.params['tenant']
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
            'aci_class': 'cloudAwsProvider',
            'aci_rn': 'awsprovider'.format(),
            'target_filter': '',
            'module_object': None
        }, 
        
        child_classes=[]
        
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudAwsProvider',
            class_config={ 
                'accessKeyId': accessKeyId,
                'accountId': accountId,
                'annotation': annotation,
                'descr': descr,
                'email': email,
                'httpProxy': httpProxy,
                'isAccountInOrg': isAccountInOrg,
                'isTrusted': isTrusted,
                'name': name,
                'nameAlias': nameAlias,
                'ownerKey': ownerKey,
                'ownerTag': ownerTag,
                'providerId': providerId,
                'region': region,
                'secretAccessKey': secretAccessKey,
            },
            child_configs=child_configs
           
        )

        aci.get_diff(aci_class='cloudAwsProvider')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()