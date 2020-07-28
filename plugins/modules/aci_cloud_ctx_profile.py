#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, nkatarmal-crest <nirav.katarmal@crestdatasys.com>
# Copyright: (c) 2020, Cindy Zhao <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloud_ctx_profile
short_description: Manage the Cloud Context Profile objects on Cisco Cloud ACI.
description:
- Mo doc not defined in techpub!!!
notes:
- More information about the internal APIC class B(cloud:CtxProfile) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Nirav (@crestdatasys)
- Cindy Zhao (@cizhao)
options:
  name:
    description:
    - The name of the Cloud Context Profile
    type: str
    aliases: [ cloud_context_profile ]
  description:
    description:
    - Description of the Cloud Context Profile
    type: str
  name_alias:
    description:
    - An alias for the name of the current object. This relates to the nameAlias field in ACI and is used to rename object without changing the DN
    type: str
  tenant:
    description:
    - The name of the Tenant.
    type: str
  primary_cidr:
    description:
    - The subnet with netmask to use as primary CIDR block for the Cloud Context Profile.
    type: str
  vrf:
    description:
    - The name of the VRF.
    type: str
  region:
    description:
    - The name of the cloud region in which to deploy the network construct.
    type: str
  vpn_gateway:
    description:
    - Determine if a VPN Gateway Router will be deployed or not.
    type: bool
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    choices: [ absent, present, query ]
    type: str
    default: present

extends_documentation_fragment:
- cisco.aci.aci
'''

EXAMPLES = r'''
- name: Add a new aci cloud ctx profile
  aci_cloud_ctx_profile:
    host: apic_host
    username: admin
    password: SomeSecretPassword
    tenant: tenant_1
    name: cloud_ctx_profile
    vrf: VRF1
    region: us-west-1
    primary_cidr: '10.0.10.1/16'
    state: present
  delegate_to: localhost

- name: Remove an aci cloud ctx profile
  aci_cloud_ctx_profile:
    host: apic_host
    username: admin
    password: SomeSecretPassword
    tenant: tenant_1
    name: cloud_ctx_profile
    state: absent
  delegate_to: localhost

- name: Query a specific aci cloud ctx profile
  aci_cloud_ctx_profile:
    host: apic_host
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    name: ctx_profile_1
    state: query
  delegate_to: localhost

- name: Query all aci cloud ctx profile
  aci_cloud_ctx_profile:
    host: apic_host
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    state: query
  delegate_to: localhost
'''


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        description=dict(type='str',),
        name=dict(type='str', aliases=['cloud_context_profile']),
        name_alias=dict(type='str',),
        tenant=dict(type='str',),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
        primary_cidr=dict(type='str',),
        # FIXME: didn't find the flow_log in UI
        # flow_log=dict(type='str'),
        vrf=dict(type='str'),
        region=dict(type='str'),
        vpn_gateway=dict(type='bool', default=False)
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['name', 'tenant']],
            ['state', 'present', ['name', 'tenant', 'vrf', 'region', 'primary_cidr']],
        ],
    )

    description = module.params.get('description')
    name = module.params.get('name')
    name_alias = module.params.get('name_alias')
    tenant = module.params.get('tenant')
    state = module.params.get('state')
    primary_cidr = module.params.get('primary_cidr')
    child_configs = []

    vrf = module.params.get('vrf')
    region = module.params.get('region')
    vpn_gateway = module.params.get('vpn_gateway')

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
            aci_rn='ctxprofile-{0}'.format(name),
            target_filter='eq(cloudCtxProfile.name, "{0}")'.format(name),
            module_object=name
        ),
        child_classes=['cloudRsToCtx', 'cloudRsCtxProfileToRegion', 'cloudRouterP', 'cloudCidr']
    )

    aci.get_existing()

    if state == 'present':
        child_configs.append(dict(cloudRsToCtx=dict(attributes=dict(tnFvCtxName=vrf))))
        child_configs.append(dict(
            cloudRsCtxProfileToRegion=dict(
                attributes=dict(
                    tDn="uni/clouddomp/provp-aws/region-{0}".format(region)
                )
            )
        ))
        if vpn_gateway:
            child_configs.append(dict(
                cloudRouterP=dict(
                    attributes=dict(
                        name="default"
                    ),
                    children=[dict(
                        cloudIntNetworkP=dict(
                            attributes=dict(
                                name="default"
                            )
                        )
                    )]
                )
            ))
        child_configs.append(dict(
            cloudCidr=dict(
                attributes=dict(
                    addr=primary_cidr,
                    primary="yes"
                )
            )
        ))
        aci.payload(
            aci_class='cloudCtxProfile',
            class_config=dict(
                description=description,
                name=name,
                name_alias=name_alias,
                type='regular',
            ),
            child_configs=child_configs
        )

        aci.get_diff(aci_class='cloudCtxProfile')
        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
