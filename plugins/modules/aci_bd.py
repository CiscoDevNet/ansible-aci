#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
---
module: aci_bd
short_description: Manage Bridge Domains (BD) objects (fv:BD)
description:
- Manages Bridge Domains (BD) on Cisco ACI fabrics.
options:
  arp_flooding:
    description:
    - Determines if the Bridge Domain should flood ARP traffic.
    - The APIC defaults to C(no) when unset during creation.
    type: bool
  bd:
    description:
    - The name of the Bridge Domain.
    type: str
    aliases: [ bd_name, name ]
  bd_type:
    description:
    - The type of traffic on the Bridge Domain.
    - The APIC defaults to C(ethernet) when unset during creation.
    type: str
    choices: [ ethernet, fc ]
  description:
    description:
    - Description for the Bridge Domain.
    type: str
  enable_multicast:
    description:
    - Determines if PIM is enabled.
    - The APIC defaults to C(no) when unset during creation.
    type: bool
  enable_routing:
    description:
    - Determines if IP forwarding should be allowed.
    - The APIC defaults to C(yes) when unset during creation.
    type: bool
  endpoint_clear:
    description:
    - Clears all End Points in all Leaves when C(yes).
    - The value is not reset to disabled once End Points have been cleared; that requires a second task.
    - The APIC defaults to C(no) when unset during creation.
    type: bool
  endpoint_move_detect:
    description:
    - Determines if GARP should be enabled to detect when End Points move.
    - The APIC defaults to C(garp) when unset during creation.
    type: str
    choices: [ default, garp ]
  endpoint_retention_action:
    description:
    - Determines if the Bridge Domain should inherit or resolve the End Point Retention Policy.
    - The APIC defaults to C(resolve) when unset during creation.
    type: str
    choices: [ inherit, resolve ]
  endpoint_retention_policy:
    description:
    - The name of the End Point Retention Policy the Bridge Domain should use when
      overriding the default End Point Retention Policy.
    type: str
  igmp_snoop_policy:
    description:
    - The name of the IGMP Snooping Policy the Bridge Domain should use when
      overriding the default IGMP Snooping Policy.
    type: str
  ip_learning:
    description:
    - Determines if the Bridge Domain should learn End Point IPs.
    - The APIC defaults to C(yes) when unset during creation.
    type: bool
  ipv6_nd_policy:
    description:
    - The name of the IPv6 Neighbor Discovery Policy the Bridge Domain should use when
      overridding the default IPV6 ND Policy.
    type: str
  l2_unknown_unicast:
    description:
    - Determines what forwarding method to use for unknown l2 destinations.
    - The APIC defaults to C(proxy) when unset during creation.
    type: str
    choices: [ proxy, flood ]
  l3_unknown_multicast:
    description:
    - Determines the forwarding method to use for unknown multicast destinations.
    - The APIC defaults to C(flood) when unset during creation.
    type: str
    choices: [ flood, opt-flood ]
  limit_ip_learn:
    description:
    - Determines if the BD should limit IP learning to only subnets owned by the Bridge Domain.
    - The APIC defaults to C(yes) when unset during creation.
    type: bool
  mac_address:
    description:
    - The MAC Address to assign to the C(bd) instead of using the default.
    - The APIC defaults to C(00:22:BD:F8:19:FF) when unset during creation.
    type: str
    aliases: [ mac ]
  multi_dest:
    description:
    - Determines the forwarding method for L2 multicast, broadcast, and link layer traffic.
    - The APIC defaults to C(bd-flood) when unset during creation.
    type: str
    choices: [ bd-flood, drop, encap-flood ]
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
  tenant:
    description:
    - The name of the Tenant.
    type: str
    aliases: [ tenant_name ]
  vrf:
    description:
    - The name of the VRF.
    type: str
    aliases: [ vrf_name ]
extends_documentation_fragment:
- cisco.aci.aci

notes:
- The C(tenant) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:BD).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Jacob McGill (@jmcgill298)
'''

EXAMPLES = r'''
- name: Add Bridge Domain
  cisco.aci.aci_bd:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: no
    tenant: prod
    bd: web_servers
    mac_address: 00:22:BD:F8:19:FE
    vrf: prod_vrf
    state: present
  delegate_to: localhost

- name: Add an FC Bridge Domain
  cisco.aci.aci_bd:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: no
    tenant: prod
    bd: storage
    bd_type: fc
    vrf: fc_vrf
    enable_routing: no
    state: present
  delegate_to: localhost

- name: Modify a Bridge Domain
  cisco.aci.aci_bd:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: yes
    tenant: prod
    bd: web_servers
    arp_flooding: yes
    l2_unknown_unicast: flood
    state: present
  delegate_to: localhost

- name: Query All Bridge Domains
  cisco.aci.aci_bd:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: yes
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a Bridge Domain
  cisco.aci.aci_bd:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: yes
    tenant: prod
    bd: web_servers
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a Bridge Domain
  cisco.aci.aci_bd:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: yes
    tenant: prod
    bd: web_servers
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
        arp_flooding=dict(type='bool'),
        bd=dict(type='str', aliases=['bd_name', 'name']),  # Not required for querying all objects
        bd_type=dict(type='str', choices=['ethernet', 'fc']),
        description=dict(type='str'),
        enable_multicast=dict(type='bool'),
        enable_routing=dict(type='bool'),
        endpoint_clear=dict(type='bool'),
        endpoint_move_detect=dict(type='str', choices=['default', 'garp']),
        endpoint_retention_action=dict(type='str', choices=['inherit', 'resolve']),
        endpoint_retention_policy=dict(type='str'),
        igmp_snoop_policy=dict(type='str'),
        ip_learning=dict(type='bool'),
        ipv6_nd_policy=dict(type='str'),
        l2_unknown_unicast=dict(type='str', choices=['proxy', 'flood']),
        l3_unknown_multicast=dict(type='str', choices=['flood', 'opt-flood']),
        limit_ip_learn=dict(type='bool'),
        mac_address=dict(type='str', aliases=['mac']),
        multi_dest=dict(type='str', choices=['bd-flood', 'drop', 'encap-flood']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
        tenant=dict(type='str', aliases=['tenant_name']),  # Not required for querying all objects
        vrf=dict(type='str', aliases=['vrf_name']),
        name_alias=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['bd', 'tenant']],
            ['state', 'present', ['bd', 'tenant']],
        ],
    )

    aci = ACIModule(module)

    arp_flooding = aci.boolean(module.params.get('arp_flooding'))
    bd = module.params.get('bd')
    bd_type = module.params.get('bd_type')
    if bd_type == 'ethernet':
        # ethernet type is represented as regular, but that is not clear to the users
        bd_type = 'regular'
    description = module.params.get('description')
    enable_multicast = aci.boolean(module.params.get('enable_multicast'))
    enable_routing = aci.boolean(module.params.get('enable_routing'))
    endpoint_clear = aci.boolean(module.params.get('endpoint_clear'))
    endpoint_move_detect = module.params.get('endpoint_move_detect')
    if endpoint_move_detect == 'default':
        # the ACI default setting is an empty string, but that is not a good input value
        endpoint_move_detect = ''
    endpoint_retention_action = module.params.get('endpoint_retention_action')
    endpoint_retention_policy = module.params.get('endpoint_retention_policy')
    igmp_snoop_policy = module.params.get('igmp_snoop_policy')
    ip_learning = aci.boolean(module.params.get('ip_learning'))
    ipv6_nd_policy = module.params.get('ipv6_nd_policy')
    l2_unknown_unicast = module.params.get('l2_unknown_unicast')
    l3_unknown_multicast = module.params.get('l3_unknown_multicast')
    limit_ip_learn = aci.boolean(module.params.get('limit_ip_learn'))
    mac_address = module.params.get('mac_address')
    multi_dest = module.params.get('multi_dest')
    state = module.params.get('state')
    tenant = module.params.get('tenant')
    vrf = module.params.get('vrf')
    name_alias = module.params.get('name_alias')

    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant},
        ),
        subclass_1=dict(
            aci_class='fvBD',
            aci_rn='BD-{0}'.format(bd),
            module_object=bd,
            target_filter={'name': bd},
        ),
        child_classes=['fvRsCtx', 'fvRsIgmpsn', 'fvRsBDToNdP', 'fvRsBdToEpRet'],
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='fvBD',
            class_config=dict(
                arpFlood=arp_flooding,
                descr=description,
                epClear=endpoint_clear,
                epMoveDetectMode=endpoint_move_detect,
                ipLearning=ip_learning,
                limitIpLearnToSubnets=limit_ip_learn,
                mac=mac_address,
                mcastAllow=enable_multicast,
                multiDstPktAct=multi_dest,
                name=bd,
                type=bd_type,
                unicastRoute=enable_routing,
                unkMacUcastAct=l2_unknown_unicast,
                unkMcastAct=l3_unknown_multicast,
                nameAlias=name_alias,
            ),
            child_configs=[
                {'fvRsCtx': {'attributes': {'tnFvCtxName': vrf}}},
                {'fvRsIgmpsn': {'attributes': {'tnIgmpSnoopPolName': igmp_snoop_policy}}},
                {'fvRsBDToNdP': {'attributes': {'tnNdIfPolName': ipv6_nd_policy}}},
                {'fvRsBdToEpRet': {'attributes': {'resolveAct': endpoint_retention_action, 'tnFvEpRetPolName': endpoint_retention_policy}}},
            ],
        )

        aci.get_diff(aci_class='fvBD')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
