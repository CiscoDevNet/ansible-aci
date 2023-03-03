#!/usr/bin/python

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = r'''
---
module: aci_interface_policy_storm_control
short_description: Manage Storm Control interface policies (stormctrl:IfPol)
description:
- Manage CDP interface policies on Cisco ACI fabrics.
options:
  stormctrl_policy:
    description:
    - The Storm Control interface policy name.
    type: str
    aliases: [ name ]
  description:
    description:
    - The description for the Storm interface policy name.
    type: str
    aliases: [ descr ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
  rate:
    description:
    - The bandwidth rate for all packet types.
    type: int
  burstRate:
    description:
    - The bandwidth burst rate of all packet types.
    type: int
  bcRate:
    description:
    - The bandwidth rate for broadcast packets.
    type: int
  bcBurstRate:
    description:
    - The bandwidth burst rate for broadcast packets.
    type: int
  mcRate:
    description:
    - The bandwidth rate for multicast packets.
    type: int
  mcBurstRate:
    description:
    - The bandwidth burst rate for multicast packets.
    type: int
  uucRate:
    description:
    - The bandwidth rate for unknown unicast packets.
    type: int
  uucBurstRate:
    description:
    - The bandwidth burst rate for unknown unicast packets.
    type: int
  ratePps:
    description:
    - The packet per second rate for all packet types.
    type: int
  burstPps:
    description:
    - The packet per second burst rate for all packet types.
    type: int
  bcRatePps:
    description:
    - The packet per second rate for broadcast packets.
    type: int
  bcBurstPps:
    description:
    - The packet per second burst rate for broadcast packets.
    type: int
  mcRatePps:
    description:
    - The packet per second rate for multicast packets.
    type: int
  mcBurstPps:
    description:
    - The packet per second burst rate for multicast packets.
    type: int
  uucRatePps:
    description:
    - The packet per second rate for unknown unicast packets.
    type: int
  uucBurstPps:
    description:
    - The packet per second burst rate for unknown unicast packets.
    type: int
  isUcMcBcStormPktCfgValid:
    description:
    - Whether or not the per-packet type numbers are valid.
    type: str
    choices: [Valid, Invalid]
  stormCtrlAction:
    type: str
    choices: [drop, shutdown]
    description:
    - The storm control action to take when triggered.
  stormCtrlSoakInstCount:
    type: int
    description:
    - The number of instances before triggering.
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(stormctrl:IfPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Eric Girard (@netgirard)
'''

EXAMPLES = r'''
- name: Create CDP Interface Policy to enable CDP
  cisco.aci.aci_interface_policy_cdp:
    name: Ansible_CDP_Interface_Policy
    host: apic.example.com
    username: admin
    password: adminpass
    admin_state: true
    state: present

- name: Create CDP Interface Policy to disable CDP
  cisco.aci.aci_interface_policy_cdp:
    name: Ansible_CDP_Interface_Policy
    host: apic.example.com
    username: admin
    password: adminpass
    admin_state: false
    state: present

- name: Remove CDP Interface Policy
  cisco.aci.aci_interface_policy_cdp:
    name: Ansible_CDP_Interface_Policy
    host: apic.example.com
    username: admin
    password: adminpass
    output_level: debug
    state: absent

- name: Query CDP Policy
  cisco.aci.aci_interface_policy_cdp:
    host: apic.example.com
    username: admin
    password: adminpass
    state: query
'''

RETURN = r'''
current:
  description: The existing configuration from the APIC after the module has finished
  returned: success
  type: list
  sample:
    [
        {
            "cdpIfPol": {
                "attributes": {
                    "adminSt": "disabled",
                    "annotation": "",
                    "descr": "Ansible Created CDP Test Policy",
                    "dn": "uni/infra/cdpIfP-Ansible_CDP_Test_Policy",
                    "name": "Ansible_CDP_Test_Policy",
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec

from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        stormctrl_policy=dict(type='str', required=False, aliases=['name']),  # Not required for querying all objects
        description=dict(type='str', aliases=['descr']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
        name_alias=dict(type='str'),
        rate=dict(type='int'),
        burstRate=dict(type='int'),
        bcRate=dict(type='int'),
        bcBurstRate=dict(type='int'),
        mcRate=dict(type='int'),
        mcBurstRate=dict(type='int'),
        uucRate=dict(type='int'),
        uucBurstRate=dict(type='int'),
        ratePps=dict(type='int'),
        burstPps=dict(type='int'),
        bcRatePps=dict(type='int'),
        bcBurstPps=dict(type='int'),
        mcRatePps=dict(type='int'),
        mcBurstPps=dict(type='int'),
        uucRatePps=dict(type='int'),
        uucBurstPps=dict(type='int'),
        isUcMcBcStormPktCfgValid=dict(type='str', choices=['Valid', 'Invalid']),
        stormCtrlAction=dict(type='str', choices=['drop', 'shutdown']),
        stormCtrlSoakInstCount=dict(type='int'),

    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['stormctrl_policy']],
            ['state', 'present', ['stormctrl_policy', 'isUcMcBcStormPktCfgValid']],
            ['isUcMcBcStormPktCfgValid', 'Valid', ['bcRate', 'bcRatePps'], True],
            ['isUcMcBcStormPktCfgValid', 'Invalid', ['rate', 'ratePps'], True],
        ],
        required_together=[
            ('rate', 'burstRate'),
            ('bcRate', 'bcBurstRate', 'mcRate', 'mcBurstRate', 'uucRate', 'uucBurstRate'),
            ('ratePps', 'burstPps'),
            ('bcRatePps', 'bcBurstPps', 'mcRatePps', 'mcBurstPps', 'uucRatePps', 'uucBurstPps'),
        ],
        mutually_exclusive=[
            ('rate', 'bcRate', 'ratePps', 'bcRatePps'),
        ],
    )

    aci = ACIModule(module)

    stormctrl_policy = module.params.get('stormctrl_policy')
    description = module.params.get('description')
    state = module.params.get('state')
    name_alias = module.params.get('name_alias')
    isUcMcBcStormPktCfgValid = module.params.get('isUcMcBcStormPktCfgValid')
    stormCtrlAction = module.params.get('stormCtrlAction')
    stormCtrlSoakInstCount = module.params.get('stormCtrlSoakInstCount')

    rate_keys = [
        'rate', 'burstRate', 'bcRate', 'bcBurstRate', 'mcRate', 'mcBurstRate', 'uucRate', 'uucBurstRate',
        'ratePps', 'burstPps', 'bcRatePps', 'bcBurstPps', 'mcRatePps', 'mcBurstPps', 'uucRatePps', 'uucBurstPps'
    ]
    rates = {}

    for key in rate_keys:
        if module.params.get(key) is not None and 'Pps' not in key:
            value = module.params.get(key)
            if 0 <= value <= 100:
                rates[key] = '{0:.6f}'.format(module.params.get(key))
            else:
                module.fail_json(msg="Argument {0} needs to be a value between 0 and 100 inclusive, got {1}".format(key, value))
        else:
            rates[key] = module.params.get(key)

    if any(rates[k] is not None for k in ['rate', 'burstRate', 'bcRate', 'bcBurstRate', 'mcRate', 'mcBurstRate', 'uucRate', 'uucBurstRate']):
        for pps in ['ratePps', 'burstPps', 'bcRatePps', 'bcBurstPps', 'mcRatePps', 'mcBurstPps', 'uucRatePps', 'uucBurstPps']:
            rates[pps] = None

    aci.construct_url(
        root_class=dict(
            aci_class='stormctrlIfPol',
            aci_rn='infra/stormctrlifp-{0}'.format(stormctrl_policy),
            module_object=stormctrl_policy,
            target_filter={'name': stormctrl_policy},
        ),
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='stormctrlIfPol',
            class_config=dict(
                name=stormctrl_policy,
                descr=description,
                nameAlias=name_alias,
                isUcMcBcStormPktCfgValid=isUcMcBcStormPktCfgValid,
                stormCtrlAction=stormCtrlAction,
                stormCtrlSoakInstCount=stormCtrlSoakInstCount,
                **rates
            ),
        )

        aci.get_diff(aci_class='stormctrlIfPol')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == '__main__':
    main()
