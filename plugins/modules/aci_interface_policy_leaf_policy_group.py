#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Bruno Calogero <brunocalogero@hotmail.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
---
module: aci_interface_policy_leaf_policy_group
short_description: Manage fabric interface policy leaf policy groups (infra:AccBndlGrp, infra:AccPortGrp)
description:
- Manage fabric interface policy leaf policy groups on Cisco ACI fabrics.
options:
  policy_group:
    description:
    - Name of the leaf policy group to be added/deleted.
    type: str
    aliases: [ name, policy_group_name ]
  description:
    description:
    - Description for the leaf policy group to be created.
    type: str
    aliases: [ descr ]
  lag_type:
    description:
    - Selector for the type of leaf policy group we want to create.
    - C(leaf) for Leaf Access Port Policy Group
    - C(link) for Port Channel (PC)
    - C(node) for Virtual Port Channel (VPC)
    type: str
    required: yes
    choices: [ leaf, link, node ]
    aliases: [ lag_type_name ]
  link_level_policy:
    description:
    - Choice of link_level_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ link_level_policy_name ]
  cdp_policy:
    description:
    - Choice of cdp_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ cdp_policy_name ]
  mcp_policy:
    description:
    - Choice of mcp_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ mcp_policy_name ]
  lldp_policy:
    description:
    - Choice of lldp_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ lldp_policy_name ]
  stp_interface_policy:
    description:
    - Choice of stp_interface_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ stp_interface_policy_name ]
  egress_data_plane_policing_policy:
    description:
    - Choice of egress_data_plane_policing_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ egress_data_plane_policing_policy_name ]
  ingress_data_plane_policing_policy:
    description:
    - Choice of ingress_data_plane_policing_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ ingress_data_plane_policing_policy_name ]
  priority_flow_control_policy:
    description:
    - Choice of priority_flow_control_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ priority_flow_control_policy_name ]
  fibre_channel_interface_policy:
    description:
    - Choice of fibre_channel_interface_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ fibre_channel_interface_policy_name ]
  slow_drain_policy:
    description:
    - Choice of slow_drain_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ slow_drain_policy_name ]
  port_channel_policy:
    description:
    - Choice of port_channel_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ port_channel_policy_name ]
  monitoring_policy:
    description:
    - Choice of monitoring_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ monitoring_policy_name ]
  storm_control_interface_policy:
    description:
    - Choice of storm_control_interface_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ storm_control_interface_policy_name ]
  l2_interface_policy:
    description:
    - Choice of l2_interface_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ l2_interface_policy_name ]
  port_security_policy:
    description:
    - Choice of port_security_policy to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ port_security_policy_name ]
  aep:
    description:
    - Choice of attached_entity_profile (AEP) to be used as part of the leaf policy group to be created.
    type: str
    aliases: [ aep_name ]
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
extends_documentation_fragment:
- cisco.aci.aci

notes:
- When using the module please select the appropriate link_aggregation_type (lag_type).
  C(link) for Port Channel(PC), C(node) for Virtual Port Channel(VPC) and C(leaf) for Leaf Access Port Policy Group.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(infra:AccBndlGrp) and B(infra:AccPortGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Bruno Calogero (@brunocalogero)
'''

EXAMPLES = r'''
- name: Create a Port Channel (PC) Interface Policy Group
  cisco.aci.aci_interface_policy_leaf_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: link
    policy_group: policygroupname
    description: policygroupname description
    link_level_policy: whateverlinklevelpolicy
    cdp_policy: whatevercdppolicy
    lldp_policy: whateverlldppolicy
    port_channel_policy: whateverlacppolicy
    state: present
  delegate_to: localhost

- name: Create a Virtual Port Channel (VPC) Interface Policy Group
  cisco.aci.aci_interface_policy_leaf_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: node
    policy_group: policygroupname
    link_level_policy: whateverlinklevelpolicy
    cdp_policy: whatevercdppolicy
    lldp_policy: whateverlldppolicy
    port_channel_policy: whateverlacppolicy
    state: present
  delegate_to: localhost

- name: Create a Leaf Access Port Policy Group
  cisco.aci.aci_interface_policy_leaf_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: leaf
    policy_group: policygroupname
    link_level_policy: whateverlinklevelpolicy
    cdp_policy: whatevercdppolicy
    lldp_policy: whateverlldppolicy
    state: present
  delegate_to: localhost

- name: Query all Leaf Access Port Policy Groups of type link
  cisco.aci.aci_interface_policy_leaf_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: link
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific Lead Access Port Policy Group
  cisco.aci.aci_interface_policy_leaf_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: leaf
    policy_group: policygroupname
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete an Interface policy Leaf Policy Group
  cisco.aci.aci_interface_policy_leaf_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: leaf
    policy_group: policygroupname
    state: absent
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        # NOTE: Since this module needs to include both infra:AccBndlGrp (for PC and VPC) and infra:AccPortGrp (for leaf access port policy group):
        # NOTE: I'll allow the user to make the choice here (link(PC), node(VPC), leaf(leaf-access port policy group))
        lag_type=dict(type='str', required=True, aliases=['lag_type_name'], choices=['leaf', 'link', 'node']),
        policy_group=dict(type='str', aliases=['name', 'policy_group_name']),  # Not required for querying all objects
        description=dict(type='str', aliases=['descr']),
        link_level_policy=dict(type='str', aliases=['link_level_policy_name']),
        cdp_policy=dict(type='str', aliases=['cdp_policy_name']),
        mcp_policy=dict(type='str', aliases=['mcp_policy_name']),
        lldp_policy=dict(type='str', aliases=['lldp_policy_name']),
        stp_interface_policy=dict(type='str', aliases=['stp_interface_policy_name']),
        egress_data_plane_policing_policy=dict(type='str', aliases=['egress_data_plane_policing_policy_name']),
        ingress_data_plane_policing_policy=dict(type='str', aliases=['ingress_data_plane_policing_policy_name']),
        priority_flow_control_policy=dict(type='str', aliases=['priority_flow_control_policy_name']),
        fibre_channel_interface_policy=dict(type='str', aliases=['fibre_channel_interface_policy_name']),
        slow_drain_policy=dict(type='str', aliases=['slow_drain_policy_name']),
        port_channel_policy=dict(type='str', aliases=['port_channel_policy_name']),
        monitoring_policy=dict(type='str', aliases=['monitoring_policy_name']),
        storm_control_interface_policy=dict(type='str', aliases=['storm_control_interface_policy_name']),
        l2_interface_policy=dict(type='str', aliases=['l2_interface_policy_name']),
        port_security_policy=dict(type='str', aliases=['port_security_policy_name']),
        aep=dict(type='str', aliases=['aep_name']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
        name_alias=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['policy_group']],
            ['state', 'present', ['policy_group']],
        ],
    )

    policy_group = module.params.get('policy_group')
    description = module.params.get('description')
    lag_type = module.params.get('lag_type')
    link_level_policy = module.params.get('link_level_policy')
    cdp_policy = module.params.get('cdp_policy')
    mcp_policy = module.params.get('mcp_policy')
    lldp_policy = module.params.get('lldp_policy')
    stp_interface_policy = module.params.get('stp_interface_policy')
    egress_data_plane_policing_policy = module.params.get('egress_data_plane_policing_policy')
    ingress_data_plane_policing_policy = module.params.get('ingress_data_plane_policing_policy')
    priority_flow_control_policy = module.params.get('priority_flow_control_policy')
    fibre_channel_interface_policy = module.params.get('fibre_channel_interface_policy')
    slow_drain_policy = module.params.get('slow_drain_policy')
    port_channel_policy = module.params.get('port_channel_policy')
    monitoring_policy = module.params.get('monitoring_policy')
    storm_control_interface_policy = module.params.get('storm_control_interface_policy')
    l2_interface_policy = module.params.get('l2_interface_policy')
    port_security_policy = module.params.get('port_security_policy')
    aep = module.params.get('aep')
    state = module.params.get('state')
    name_alias = module.params.get('name_alias')

    if lag_type == 'leaf':
        aci_class_name = 'infraAccPortGrp'
        dn_name = 'accportgrp'
        class_config_dict = dict(
            name=policy_group,
            descr=description,
            nameAlias=name_alias,
        )
        # Reset for target_filter
        lag_type = None
    elif lag_type in ('link', 'node'):
        aci_class_name = 'infraAccBndlGrp'
        dn_name = 'accbundle'
        class_config_dict = dict(
            name=policy_group,
            descr=description,
            lagT=lag_type,
            nameAlias=name_alias,
        )

    child_configs = [
        dict(
            infraRsCdpIfPol=dict(
                attributes=dict(
                    tnCdpIfPolName=cdp_policy,
                ),
            ),
        ),
        dict(
            infraRsFcIfPol=dict(
                attributes=dict(
                    tnFcIfPolName=fibre_channel_interface_policy,
                ),
            ),
        ),
        dict(
            infraRsHIfPol=dict(
                attributes=dict(
                    tnFabricHIfPolName=link_level_policy,
                ),
            ),
        ),
        dict(
            infraRsL2IfPol=dict(
                attributes=dict(
                    tnL2IfPolName=l2_interface_policy,
                ),
            ),
        ),
        dict(
            infraRsL2PortSecurityPol=dict(
                attributes=dict(
                    tnL2PortSecurityPolName=port_security_policy,
                ),
            ),
        ),
        dict(
            infraRsLacpPol=dict(
                attributes=dict(
                    tnLacpLagPolName=port_channel_policy,
                ),
            ),
        ),
        dict(
            infraRsLldpIfPol=dict(
                attributes=dict(
                    tnLldpIfPolName=lldp_policy,
                ),
            ),
        ),
        dict(
            infraRsMcpIfPol=dict(
                attributes=dict(
                    tnMcpIfPolName=mcp_policy,
                ),
            ),
        ),
        dict(
            infraRsMonIfInfraPol=dict(
                attributes=dict(
                    tnMonInfraPolName=monitoring_policy,
                ),
            ),
        ),
        dict(
            infraRsQosEgressDppIfPol=dict(
                attributes=dict(
                    tnQosDppPolName=egress_data_plane_policing_policy,
                ),
            ),
        ),
        dict(
            infraRsQosIngressDppIfPol=dict(
                attributes=dict(
                    tnQosDppPolName=ingress_data_plane_policing_policy,
                ),
            ),
        ),
        dict(
            infraRsQosPfcIfPol=dict(
                attributes=dict(
                    tnQosPfcIfPolName=priority_flow_control_policy,
                ),
            ),
        ),
        dict(
            infraRsQosSdIfPol=dict(
                attributes=dict(
                    tnQosSdIfPolName=slow_drain_policy,
                ),
            ),
        ),
        dict(
            infraRsStormctrlIfPol=dict(
                attributes=dict(
                    tnStormctrlIfPolName=storm_control_interface_policy,
                ),
            ),
        ),
        dict(
            infraRsStpIfPol=dict(
                attributes=dict(
                    tnStpIfPolName=stp_interface_policy,
                ),
            ),
        ),
    ]

    # Add infraRsattEntP binding only when aep was defined
    if aep is not None:
        child_configs.append(dict(
            infraRsAttEntP=dict(
                attributes=dict(
                    tDn='uni/infra/attentp-{0}'.format(aep),
                ),
            ),
        ))

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class=aci_class_name,
            aci_rn='infra/funcprof/{0}-{1}'.format(dn_name, policy_group),
            module_object=policy_group,
            target_filter={'name': policy_group, 'lagT': lag_type},
        ),
        child_classes=[
            'infraRsAttEntP',
            'infraRsCdpIfPol',
            'infraRsFcIfPol',
            'infraRsHIfPol',
            'infraRsL2IfPol',
            'infraRsL2PortSecurityPol',
            'infraRsLacpPol',
            'infraRsLldpIfPol',
            'infraRsMcpIfPol',
            'infraRsMonIfInfraPol',
            'infraRsQosEgressDppIfPol',
            'infraRsQosIngressDppIfPol',
            'infraRsQosPfcIfPol',
            'infraRsQosSdIfPol',
            'infraRsStormctrlIfPol',
            'infraRsStpIfPol',
        ],
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class=aci_class_name,
            class_config=class_config_dict,
            child_configs=child_configs,
        )

        aci.get_diff(aci_class=aci_class_name)

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
