#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, nkatarmal-crest <nirav.katarmal@crestdatasys.com>
# Copyright: (c) 2020, Cindy Zhao <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloud_subnet
short_description: Manage Cloud Subnet (cloud:Subnet)
description:
- Manage Cloud Subnet on Cisco Cloud ACI.
notes:
- More information about the internal APIC class B(cloud:Subnet) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Nirav (@nirav)
- Cindy Zhao (@cizhao)
options:
  name:
    description:
    - The name of the Cloud Subnet.
    type: str
    aliases: [subnet]
  description:
    description:
    - Description of the Cloud Subnet.
    type: str
  address:
    description:
    - Ip address of the Cloud Subnet.
    type: str
  name_alias:
    description:
    - An alias for the name of the current object. This relates to the nameAlias field in ACI and is used to rename object without changing the DN.
    type: str
  scope:
    description:
    - capability domain
    choices: [ private, public, shared ]
    type: str
  usage:
    description:
    - usage of the port
    choices: [ infra-router, user ]
    type: str
  tenant:
    description:
    - The name of tenant.
    type: str
  cloud_context_profile:
    description:
    - The name of cloud context profile.
    type: str
  cloud_cidr:
    description:
    - Address of cloud cidr.
    type: str
  cloud_zone_attach:
    description:
    - The cloud zone which is attached to the given cloud context profile.
    - Only used when it is an aws cloud apic.
    type: str
  vNet_gateway:
    description:
    - Determine if a vNet Gateway Router will be deployed or not.
    - Only used when it is an azure cloud apic.
    type: bool
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
- name: Create aci cloud subnet
  cisco.aci.aci_cloud_subnet:
    host: apic
    username: userName
    password: somePassword
    validate_certs: no
    tenant: anstest
    cloud_context_profile: aws_cloudCtxProfile
    cloud_cidr: '10.10.0.0/16'
    cloud_zone_attach: us-west-1a
    address: 10.10.0.1
  delegate_to: localhost

- name: Query a specific subnet
  cisco.aci.aci_cloud_subnet:
    host: apic
    username: userName
    password: somePassword
    validate_certs: no
    tenant: anstest
    cloud_context_profile: ctx_profile_1
    cloud_cidr: '10.10.0.0/16'
    address: 10.10.0.1
    state: query
  delegate_to: localhost

- name: Query all subnets
  cisco.aci.aci_cloud_subnet:
    host: apic
    username: userName
    password: somePassword
    validate_certs: no
    tenant: anstest
    cloud_context_profile: ctx_profile_1
    cloud_cidr: '10.10.0.0/16'
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
    argument_spec.update(
        name=dict(type='str', aliases=['subnet']),
        description=dict(type='str'),
        address=dict(type='str'),
        name_alias=dict(type='str'),
        scope=dict(type='str', choices=['private', 'public', 'shared']),
        usage=dict(type='str', choices=['infra-router', 'user']),
        vNet_gateway=dict(type='bool', default=False),
        tenant=dict(type='str', required=True),
        cloud_context_profile=dict(type='str', required=True),
        cloud_cidr=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
        cloud_zone_attach=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['address']],
            ['state', 'present', ['address']],
        ],
    )

    name = module.params.get('name')
    description = module.params.get('description')
    address = module.params.get('address')
    name_alias = module.params.get('name_alias')
    scope = module.params.get('scope')
    usage = module.params.get('usage')
    vNet_gateway = module.params.get('vNet_gateway')
    tenant = module.params.get('tenant')
    cloud_context_profile = module.params.get('cloud_context_profile')
    cloud_cidr = module.params.get('cloud_cidr')
    state = module.params.get('state')
    cloud_zone_attach = module.params.get('cloud_zone_attach')
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
            aci_rn='cidr-[{0}]'.format(cloud_cidr),
            target_filter='eq(cloudCidr.addr, "{0}")'.format(cloud_cidr),
            module_object=cloud_cidr
        ),
        subclass_3=dict(
            aci_class='cloudSubnet',
            aci_rn='subnet-[{0}]'.format(address),
            target_filter='eq(cloudSubnet.ip, "{0}")'.format(address),
            module_object=address
        ),
        child_classes=['cloudRsZoneAttach']
    )

    aci.get_existing()

    if state == 'present':
        # in aws cloud apic
        if cloud_zone_attach:
            region = cloud_zone_attach[:-1]
            tDn = 'uni/clouddomp/provp-aws/region-{0}/zone-{1}'.format(region, cloud_zone_attach)
            child_configs.append({'cloudRsZoneAttach': {'attributes': {'tDn': tDn}}})
        # in azure cloud apic
        if vNet_gateway:
            usage = 'gateway'

        aci.payload(
            aci_class='cloudSubnet',
            class_config=dict(
                name=name,
                descr=description,
                ip=address,
                nameAlias=name_alias,
                scope=scope,
                usage=usage,
            ),
            child_configs=child_configs
        )

        aci.get_diff(aci_class='cloudSubnet')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
