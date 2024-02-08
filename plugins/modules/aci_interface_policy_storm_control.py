#!/usr/bin/python

# Copyright: (c) 2023, Eric Girard <@netgirard>
# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r'''
---
module: aci_interface_policy_storm_control
short_description: Manage Storm Control interface policies (stormctrl:IfPol)
description:
- Manage CDP interface policies on Cisco ACI fabrics.
options:
  storm_control_policy:
    description:
    - The Storm Control interface policy name.
    type: str
    aliases: [ storm_control, storm_control_name, name ]
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
  storm_control_types:
    description:
    - Whether or not the per-packet type numbers are valid.
    type: str
    choices: [all_types, unicast_broadcast_multicast]
  storm_control_action:
    description:
    - The storm control action to take when triggered.
    type: str
    choices: [drop, shutdown]
  storm_control_soak_action:
    description:
    - The number of instances before triggering shutdown.
    type: int
  all_types_configuration:
    description:
    - The rates configuration for all packets type.
    type: dict
    aliases: [ all_types ]
    suboptions:
      rate:
        description:
        - The rate for all packet types.
        type: str
      burst_rate:
        description:
        - The burst rate of all packet types.
        type: str
      rate_type:
        description:
        - The type of rate of all packet types.
        - Choice between percentage of the bandiwth C(percentage) or packet per second C(pps)
        type: str
        choices: [ percentage, pps ]
  broadcast_configuration:
    description:
    - The rates configuration of broadcast packets.
    type: dict
    aliases: [ broadcast ]
    suboptions:
      rate:
        description:
        - The rate for broadcast packets.
        type: str
      burst_rate:
        description:
        - The burst rate of broadcast packets.
        type: str
      rate_type:
        description:
        - The type of rate of all packet types.
        - Choice between percentage of the bandiwth C(percentage) or packet per second C(pps)
        type: str
        choices: [ percentage, pps ]
  multicast_configuration:
    description:
    - The rates configuration of multicast packets.
    type: dict
    aliases: [ multicast ]
    suboptions:
      rate:
        description:
        - The rate for multicast packets.
        type: str
      burst_rate:
        description:
        - The burst rate of multicast packets.
        type: str
      rate_type:
        description:
        - The type of rate of all packet types.
        - Choice between percentage of the bandiwth C(percentage) or packet per second C(pps)
        type: str
        choices: [ percentage, pps ]
  unicast_configuration:
    description:
    - The rates configuration of unicast packets.
    type: dict
    aliases: [ unicast ]
    suboptions:
      rate:
        description:
        - The rate for unicast packets.
        type: str
      burst_rate:
        description:
        - The burst rate of unicast packets.
        type: str
      rate_type:
        description:
        - The type of rate of all packet types.
        - Choice between percentage of the bandiwth C(percentage) or packet per second C(pps)
        type: str
        choices: [ percentage, pps ]
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
- Gaspard Micol (@gmicol)
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    aci_annotation_spec,
    aci_owner_spec,
    storm_control_policy_rate_spec,
)
from ansible_collections.cisco.aci.plugins.module_utils.constants import MATCH_STORM_CONTROL_POLICY_TYPE_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        storm_control_policy=dict(type='str', required=False, aliases=['name', 'storm_control', 'storm_control_name']),  # Not required for querying all objects
        description=dict(type='str', aliases=['descr']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
        name_alias=dict(type='str'),
        storm_control_types=dict(type='str', choices=['all_types', 'unicast_broadcast_multicast']),
        all_types_configuration=dict(type='dict', options=storm_control_policy_rate_spec(), aliases=['all_types']),
        broadcast_configuration=dict(type='dict', options=storm_control_policy_rate_spec(), aliases=['broadcast']),
        multicast_configuration=dict(type='dict', options=storm_control_policy_rate_spec(), aliases=['multicast']),
        unicast_configuration=dict(type='dict', options=storm_control_policy_rate_spec(), aliases=['unicast']),
        storm_control_action=dict(type='str', choices=['drop', 'shutdown']),
        storm_control_soak_action=dict(type='int'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['storm_control_policy']],
            ['state', 'present', ['storm_control_policy']],
        ],
        mutually_exclusive=[
            ('all_types_configuration', 'broadcast_configuration'),
            ('all_types_configuration', 'multicast_configuration'),
            ('all_types_configuration', 'unicast_configuration'),
        ],
    )

    aci = ACIModule(module)

    storm_control_policy = module.params.get('storm_control_policy')
    description = module.params.get('description')
    state = module.params.get('state')
    name_alias = module.params.get('name_alias')
    storm_control_types = MATCH_STORM_CONTROL_POLICY_TYPE_MAPPING.get(module.params.get('storm_control_types'))
    storm_control_action = module.params.get('storm_control_action')
    storm_control_soak_action = module.params.get('storm_control_soak_action')

    rates_input = {}

    stom_control_types_configs = [
        dict(
            config_input=module.params.get('all_types_configuration'),
            rates=dict(rate=dict(percentage='rate', pps='ratePps'), burst_rate=dict(percentage='burstRate', pps='burstPps'))
        ),
        dict(
            config_input=module.params.get('broadcast_configuration'),
            rates=dict(rate=dict(percentage='bcRate', pps='bcRatePps'), burst_rate=dict(percentage='bcBurstRate', pps='bcBurstPps'))
        ),
        dict(
            config_input=module.params.get('multicast_configuration'),
            rates=dict(rate=dict(percentage='mcRate', pps='mcRatePps'), burst_rate=dict(percentage='mcBurstRate', pps='mcBurstPps'))
        ),
        dict(
            config_input=module.params.get('unicast_configuration'),
            rates=dict(rate=dict(percentage='uucRate', pps='uucRatePps'), burst_rate=dict(percentage='uucBurstRate', pps='uucBurstPps'))
        ),
    ]

    for config in stom_control_types_configs:
        config_input = config.get('config_input')
        rates = config.get('rates')
        if config_input is not None:
            if config_input.get('rate_type') == 'percentage':
                for rates_type, rates_attributes in rates.items():
                    input = config_input.get(rates_type)
                    if input is not None and not (0 <= float(input) <= 100):
                        module.fail_json(
                            msg="If argument rate_type is percentage, argument {0} needs to be a value between 0 and 100 inclusive, got {1}".format(
                                rates_type,
                                input,
                            )
                        )
                    else:
                        rates_input[rates_attributes.get('percentage')] = '{0:.6f}'.format(float(input))
                        rates_input[rates_attributes.get('pps')] = 'unspecified'
            elif config_input.get('rate_type') == 'pps':
                for rates_type, rates_attributes in rates.items():
                    rates_input[rates_attributes.get('percentage')] = None
                    rates_input[rates_attributes.get('pps')] = config_input.get(rates_type)
        else:
            for rates_type, rates_attributes in rates.items():
                rates_input[rates_attributes.get('percentage')] = None
                rates_input[rates_attributes.get('pps')] = None

    aci.construct_url(
        root_class=dict(
            aci_class='infraInfra',
            aci_rn='infra',
        ),
        subclass_1=dict(
            aci_class='stormctrlIfPol',
            aci_rn='stormctrlifp-{0}'.format(storm_control_policy),
            module_object=storm_control_policy,
            target_filter={'name': storm_control_policy},
        ),
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='stormctrlIfPol',
            class_config=dict(
                name=storm_control_policy,
                descr=description,
                nameAlias=name_alias,
                isUcMcBcStormPktCfgValid=storm_control_types,
                stormCtrlAction=storm_control_action,
                stormCtrlSoakInstCount=storm_control_soak_action,
                **rates_input
            ),
        )

        aci.get_diff(aci_class='stormctrlIfPol')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == '__main__':
    main()
