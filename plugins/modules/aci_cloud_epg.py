#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Cindy Zhao <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

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
- Nirav (@nirav)
- Cindy Zhao (@cizhao)
options:
  descr:
    description:
    - Description of the Cloud EPg.
    type: str
  name:
    description:
    - The name of the Cloud EPg.
    aliases: [ cloud_epg ]
    type: str
  tenant:
    description:
    - Then name of the Tenant.
    type: str
  cloud_application_profile:
    description:
    - The name of the cloud application profile.
    type: str
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
    type: str

extends_documentation_fragment:
- cisco.aci.aci
'''

EXAMPLES = r'''
- name: Create aci cloud epg (check_mode)
  cisco.aci.aci_cloud_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    cloud_application_profile: apName
    vrf: vrfName
    descr: Aci Cloud EPG
    name: epgName
    state: present
  delegate_to: localhost

- name: Remove cloud epg
  cisco.aci.aci_cloud_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    cloud_application_profile: apName
    name: cloudName
    state: absent
  delegate_to: localhost

- name: query all
  cisco.aci.aci_cloud_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    cloud_application_profile: apName
    state: query
  delegate_to: localhost

- name: query a specific cloud epg
  cisco.aci.aci_cloud_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    cloud_application_profile: apName
    name: epgName
    state: query
  delegate_to: localhost
'''

RETURN = r'''
current:
  description: The existing configuration from the APIC after the module has finished
  returned: success
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production environment",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
error:
  description: The error information as returned from the APIC
  returned: failure
  type: dict
  sample:
    {
        "code": "122",
        "text": "unknown managed object class foo"
    }
raw:
  description: The raw output returned by the APIC REST API (xml or json)
  returned: parse error
  type: str
  sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class foo"/></imdata>'
sent:
  description: The actual/minimal configuration pushed to the APIC
  returned: info
  type: list
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment"
            }
        }
    }
previous:
  description: The original configuration from the APIC before the module has started
  returned: info
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
proposed:
  description: The assembled configuration from the user-provided parameters
  returned: info
  type: dict
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment",
                "name": "production"
            }
        }
    }
filter_string:
  description: The filter string used for the request
  returned: failure or debug
  type: str
  sample: ?rsp-prop-include=config-only
method:
  description: The HTTP method used for the request to the APIC
  returned: failure or debug
  type: str
  sample: POST
response:
  description: The HTTP response from the APIC
  returned: failure or debug
  type: str
  sample: OK (30 bytes)
status:
  description: The HTTP status from the APIC
  returned: failure or debug
  type: int
  sample: 200
url:
  description: The HTTP url used for the request to the APIC
  returned: failure or debug
  type: str
  sample: https://10.11.12.13/api/mo/uni/tn-production.json
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
    child_configs = []
    relation_cloudrscloudepgctx = module.params['vrf']

    if relation_cloudrscloudepgctx:
        child_configs.append({'cloudRsCloudEPgCtx': {'attributes': {'tnFvCtxName': relation_cloudrscloudepgctx}}})

    aci = ACIModule(module)
    aci.construct_url(
        root_class={
            'aci_class': 'fvTenant',
            'aci_rn': 'tn-{0}'.format(tenant),
            'target_filter': 'eq(fvTenant.name, "{0}")'.format(tenant),
            'module_object': tenant
        },
        subclass_1={
            'aci_class': 'cloudApp',
            'aci_rn': 'cloudapp-{0}'.format(cloud_application_profile),
            'target_filter': 'eq(cloudApp.name, "{0}")'.format(cloud_application_profile),
            'module_object': cloud_application_profile
        },
        subclass_2={
            'aci_class': 'cloudEPg',
            'aci_rn': 'cloudepg-{0}'.format(name),
            'target_filter': 'eq(cloudEPg.name, "{0}")'.format(name),
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
