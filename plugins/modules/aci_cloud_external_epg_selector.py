#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloud_external_epg_selector
short_description: Manage Cloud Endpoint Selector for External EPgs (cloud:ExtEPSelector)
description:
- Decides which endpoints belong to the EPGs based on several parameters.
notes:
- More information about the internal APIC class B(cloud:ExtEPSelector) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Devarshi Shah (@devarshishah3)
- Anvitha Jain (@anvitha-jain)
version_added: '2.7'
options:
  name:
    description:
    - The name of the Cloud Endpoint selector.
    aliases: [ selector ]
    type: str
  subnet:
    description:
    - Mo doc not defined in techpub!!!
  tenant:
    description:
    - Tenant name
    type: str
  ap:
    description:
    - Parent object name
    aliases: [ app_profile, app_profile_name, cloud_application_container ]
    type: str
  cloud_external_epg:
    description:
    - Name of Object cloud_external_epg.
    type: str
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
        'name': dict(type='str', aliases=['selector']),
        'subnet': dict(type='str'),
        'tenant': dict(type='str'),
        'cloud_external_epg': dict(type='str'),
        'ap': dict(type='str', aliases=['app_profile', 'app_profile_name', 'ap']),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),
    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['subnet', 'tenant', 'ap', 'cloud_external_epg' ]],
            ['state', 'present', ['subnet', 'tenant', 'ap', 'cloud_external_epg' ]],
        ],
    )

    name = module.params['name']
    subnet = module.params['subnet']
    tenant = module.params['tenant']
    ap = module.params['ap']
    cloud_external_epg = module.params['cloud_external_epg']
    state = module.params['state']
    child_configs = []

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
            'aci_rn': 'cloudapp-{}'.format(ap),
            'target_filter': 'eq(cloudApp.name, "{}")'.format(ap),
            'module_object': ap
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
                'name': name,
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
