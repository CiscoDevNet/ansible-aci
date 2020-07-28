#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, nkatarmal-crest <nirav.katarmal@crestdatasys.com>
# Copyright: (c) 2020, Cindy Zhao <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloud_cidr
short_description: Manage Cloud CIDR on Cisco Cloud ACI.
description:
- Mo doc not defined in techpub!!!
notes:
- More information about the internal APIC class B(cloud:Cidr) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Nirav (@nirav)
- Cindy Zhao (@cizhao)
options:
  address:
    description:
    - CIDR ip and its submask.
    type: str
  description:
    description:
    - Description of the Cloud CIDR.
    type: str
  name_alias:
    description:
    - An alias for the name of the current object. This relates to the nameAlias field in ACI and is used to rename object without changing the DN.
    type: str
  primary:
    description:
    - Whether this is the primary CIDR
    choices: [ 'yes', 'no' ]
    default: 'no'
    type: str
  tenant:
    description:
    - The name of the Tenant.
    type: str
  cloud_context_profile:
    description:
    - The name of the Cloud Context Profile.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    choices: [ absent, present, query ]
    default: present
    type: str

extends_documentation_fragment:
- cisco.aci.aci
'''


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        address=dict(type='str',),
        description=dict(type='str',),
        name_alias=dict(type='str',),
        primary=dict(type='str', default='no', choices=['no', 'yes']),
        tenant=dict(type='str'),
        cloud_context_profile=dict(type='str'),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['address', 'tenant', 'cloud_context_profile', ]],
            ['state', 'present', ['address', 'tenant', 'cloud_context_profile', ]],
        ],
    )

    address = module.params.get('address')
    description = module.params.get('description')
    name_alias = module.params.get('name_alias')
    primary = module.params.get('primary')
    tenant = module.params.get('tenant')
    cloud_context_profile = module.params.get('cloud_context_profile')
    state = module.params.get('state')
    child_configs = []

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            target_filter='eq(fvTenant.name, "{0}")'.format(tenant),
            module_object=tenant
        ),
        subclass_1=dict(
            aci_class='cloudCtxProfile',
            aci_rn='ctxprofile-{0}'.format(cloud_context_profile),
            target_filter='eq(cloudCtxProfile.name, "{0}")'.format(cloud_context_profile),
            module_object=cloud_context_profile
        ),
        subclass_2=dict(
            aci_class='cloudCidr',
            aci_rn='cidr-[{0}]'.format(address),
            target_filter='eq(cloudCidr.addr, "{0}")'.format(address),
            module_object=address
        ),

        child_classes=[]

    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudCidr',
            class_config=dict(
                addr=address,
                descr=description,
                nameAlias=name_alias,
                primary=primary,
            ),
            child_configs=child_configs
        )

        aci.get_diff(aci_class='cloudCidr')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
