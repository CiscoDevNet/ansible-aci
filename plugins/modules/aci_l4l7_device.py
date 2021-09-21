#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: aci_l4l7_device
short_description: Manage L4-L7 Devices (vns:LDevVip, vns:RsALDevToPhysDomP)
description:
- Manage L4-L7 Devices.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  device:
    description:
    - Name of L4-L7 device
    type: str
    aliases: [ device_name, logical_device_name ]
  context_aware:
    description:
      - Is device Single or Multi context aware
    type: str
    choices: [ multi, single ]
  dev_type:
    description:
    - Device type
    type: str
    choices: [ physical, virtual ]
  func_type:
    description:
    - Function type of the device
    type: str
    choices: [ None, GoTo, GoThrough, L1, L2 ]
  is_copy:
    description:
    - Is the device a copy device
    type: str
    choices: [ yes, no ]
  managed:
    description:
    - Is the device a managed device
    type: str
    choices: [ yes, no ]
  prom_mode:
    description:
    - Enable promiscuous mode
    type: str
    choices: [ yes, no ]
  svc_type:
    description:
    - Service type running on the device
    type: str
    choices: [ adc, fw, others, copy ]
  trunking:
    description:
    - Enable trunking
    type: str
    choices: [ yes, no ]
  domain:
    description:
    - Physical domain to bind to the device
    type: str
    aliases: [ domain_name ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci

notes:
- The C(tenant) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) modules can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(vnsLDevVip) and B(vnsRsALDevToPhysDomP)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
'''

EXAMPLES = r'''
- name: Add a new L4-L7 device
  cisco.aci.aci_l4l7_device:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    state: present
    domain: phys
    func_type: GoTo
    context_aware: single
    is_copy: no
    managed: no
    dev_type: physical
    svc_type: adc
    trunking: no
    prom_mode: yes
  delegate_to: localhost

- name: Delete an existing L4-L7 device
  cisco.aci.aci_l4l7_device:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    state: absent
  delegate_to: localhost

- name: Query all L4-L7 devices
  cisco.aci.aci_l4l7_device:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

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


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        tenant=dict(type='str', aliases=['tenant_name']),
        device=dict(type='str', aliases=['device_name',
                                         'logical_device_name']),
        state=dict(type='str', default='present',
                   choices=['absent', 'present', 'query']),
        context_aware=dict(type='str', choices=['single', 'multi']),
        dev_type=dict(type='str', choices=['physical', 'virtual']),
        func_type=dict(type='str', choices=['None',
                                            'GoTo',
                                            'GoThrough',
                                            'L1',
                                            'L2']),
        is_copy=dict(type='str', choices=['yes', 'no']),
        managed=dict(type='str', choices=['yes', 'no']),
        prom_mode=dict(type='str', choices=['yes', 'no']),
        svc_type=dict(type='str', choices=['adc',
                                           'fw',
                                           'others',
                                           'copy']),
        trunking=dict(type='str', choices=['yes', 'no']),
        domain=dict(type='str', aliases=['domain_name']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['tenant', 'device']],
            ['state', 'present', ['tenant', 'device']]
        ]
    )

    tenant = module.params.get('tenant')
    state = module.params.get('state')
    device = module.params.get('device')
    context_aware = module.params.get('context_aware')
    dev_type = module.params.get('dev_type')
    func_type = module.params.get('func_type')
    is_copy = module.params.get('is_copy')
    managed = module.params.get('managed')
    prom_mode = module.params.get('prom_mode')
    svc_type = module.params.get('svc_type')
    trunking = module.params.get('trunking')
    domain = module.params.get('domain')

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant},
        ),
        subclass_1=dict(
            aci_class='vnsLDevVip',
            aci_rn='lDevVip-{0}'.format(device),
            module_object=device,
            target_filter={'name': device},
        ),
        child_classes=['vnsRsALDevToPhysDomP', 'vnsCDev']
    )

    aci.get_existing()

    if state == 'present':
        if domain:
            tdn = 'uni/phys-{0}'.format(domain)
        else:
            tdn = None
        aci.payload(
            aci_class='vnsLDevVip',
            class_config=dict(
                name=device,
                contextAware='{0}-Context'.format(context_aware),
                devtype=dev_type.upper(),
                funcType=func_type,
                isCopy=is_copy,
                managed=managed,
                mode='legacy-Mode',
                promMode=prom_mode,
                svcType=svc_type.upper(),
                trunking=trunking,
            ),
            child_configs=[
                dict(
                    vnsRsALDevToPhysDomP=dict(
                        attributes=dict(
                            tDn=tdn,
                        ),
                    ),
                ),
            ],
        )

        aci.get_diff(aci_class='vnsLDevVip')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
