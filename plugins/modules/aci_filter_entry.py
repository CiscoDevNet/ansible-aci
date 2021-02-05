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
module: aci_filter_entry
short_description: Manage filter entries (vz:Entry)
description:
- Manage filter entries for a filter on Cisco ACI fabrics.
options:
  arp_flag:
    description:
    - The arp flag to use when the ether_type is arp.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ arp_reply, arp_request, unspecified ]
  description:
    description:
    - Description for the Filter Entry.
    type: str
    aliases: [ descr ]
  dst_port:
    description:
    - Used to set both destination start and end ports to the same value when ip_protocol is tcp or udp.
    - Accepted values are any valid TCP/UDP port range.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
  dst_port_end:
    description:
    - Used to set the destination end port when ip_protocol is tcp or udp.
    - Accepted values are any valid TCP/UDP port range.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
  dst_port_start:
    description:
    - Used to set the destination start port when ip_protocol is tcp or udp.
    - Accepted values are any valid TCP/UDP port range.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
  entry:
    description:
    - Then name of the Filter Entry.
    type: str
    aliases: [ entry_name, filter_entry, name ]
  ether_type:
    description:
    - The Ethernet type.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ arp, fcoe, ip, ipv4, ipv6, mac_security, mpls_ucast, trill, unspecified ]
  filter:
    description:
    - The name of Filter that the entry should belong to.
    type: str
    aliases: [ filter_name ]
  icmp_msg_type:
    description:
    - ICMPv4 message type; used when ip_protocol is icmp.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ dst_unreachable, echo, echo_reply, src_quench, time_exceeded, unspecified ]
  icmp6_msg_type:
    description:
    - ICMPv6 message type; used when ip_protocol is icmpv6.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ dst_unreachable, echo_request, echo_reply, neighbor_advertisement, neighbor_solicitation, redirect, time_exceeded, unspecified ]
  ip_protocol:
    description:
    - The IP Protocol type when ether_type is ip.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ eigrp, egp, icmp, icmpv6, igmp, igp, l2tp, ospfigp, pim, tcp, udp, unspecified ]
  state:
    description:
    - present, absent, query
    type: str
    default: present
    choices: [ absent, present, query ]
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
  stateful:
    description:
    - Determines the statefulness of the filter entry.
    type: bool
  tenant:
    description:
    - The name of the tenant.
    type: str
    aliases: [ tenant_name ]
extends_documentation_fragment:
- cisco.aci.aci

notes:
- The C(tenant) and C(filter) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_filter) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_filter
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vz:Entry).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Jacob McGill (@jmcgill298)
'''

# FIXME: Add more, better examples
EXAMPLES = r'''
- cisco.aci.aci_filter_entry:
    host: "{{ inventory_hostname }}"
    username: "{{ user }}"
    password: "{{ pass }}"
    state: "{{ state }}"
    entry: "{{ entry }}"
    tenant: "{{ tenant }}"
    ether_name: "{{  ether_name }}"
    icmp_msg_type: "{{ icmp_msg_type }}"
    filter: "{{ filter }}"
    descr: "{{ descr }}"
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

VALID_ARP_FLAGS = ['arp_reply', 'arp_request', 'unspecified']
VALID_ETHER_TYPES = ['arp', 'fcoe', 'ip', 'ipv4', 'ipv6', 'mac_security', 'mpls_ucast', 'trill', 'unspecified']
VALID_ICMP_TYPES = ['dst_unreachable', 'echo', 'echo_reply', 'src_quench', 'time_exceeded', 'unspecified']
VALID_ICMP6_TYPES = ['dst_unreachable', 'echo_request', 'echo_reply', 'neighbor_advertisement',
                     'neighbor_solicitation', 'redirect', 'time_exceeded', 'unspecified']
VALID_IP_PROTOCOLS = ['eigrp', 'egp', 'icmp', 'icmpv6', 'igmp', 'igp', 'l2tp', 'ospfigp', 'pim', 'tcp', 'udp', 'unspecified']

# mapping dicts are used to normalize the proposed data to what the APIC expects, which will keep diffs accurate
ARP_FLAG_MAPPING = dict(arp_reply='reply', arp_request='req', unspecified=None)
FILTER_PORT_MAPPING = {'443': 'https', '25': 'smtp', '80': 'http', '20': 'ftpData', '53': 'dns', '110': 'pop3', '554': 'rtsp'}
ICMP_MAPPING = {'dst_unreachable': 'dst-unreach', 'echo': 'echo', 'echo_reply': 'echo-rep', 'src_quench': 'src-quench',
                'time_exceeded': 'time-exceeded', 'unspecified': 'unspecified', 'echo-rep': 'echo-rep', 'dst-unreach': 'dst-unreach'}
ICMP6_MAPPING = dict(dst_unreachable='dst-unreach', echo_request='echo-req', echo_reply='echo-rep', neighbor_advertisement='nbr-advert',
                     neighbor_solicitation='nbr-solicit', redirect='redirect', time_exceeded='time-exceeded', unspecified='unspecified')


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        arp_flag=dict(type='str', choices=VALID_ARP_FLAGS),
        description=dict(type='str', aliases=['descr']),
        dst_port=dict(type='str'),
        dst_port_end=dict(type='str'),
        dst_port_start=dict(type='str'),
        entry=dict(type='str', aliases=['entry_name', 'filter_entry', 'name']),  # Not required for querying all objects
        ether_type=dict(choices=VALID_ETHER_TYPES, type='str'),
        filter=dict(type='str', aliases=['filter_name']),  # Not required for querying all objects
        icmp_msg_type=dict(type='str', choices=VALID_ICMP_TYPES),
        icmp6_msg_type=dict(type='str', choices=VALID_ICMP6_TYPES),
        ip_protocol=dict(choices=VALID_IP_PROTOCOLS, type='str'),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
        stateful=dict(type='bool'),
        tenant=dict(type='str', aliases=['tenant_name']),  # Not required for querying all objects
        name_alias=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['entry', 'filter', 'tenant']],
            ['state', 'present', ['entry', 'filter', 'tenant']],
        ],
    )

    aci = ACIModule(module)

    arp_flag = module.params.get('arp_flag')
    if arp_flag is not None:
        arp_flag = ARP_FLAG_MAPPING.get(arp_flag)
    description = module.params.get('description')
    dst_port = module.params.get('dst_port')
    if FILTER_PORT_MAPPING.get(dst_port) is not None:
        dst_port = FILTER_PORT_MAPPING.get(dst_port)
    dst_end = module.params.get('dst_port_end')
    if FILTER_PORT_MAPPING.get(dst_end) is not None:
        dst_end = FILTER_PORT_MAPPING.get(dst_end)
    dst_start = module.params.get('dst_port_start')
    if FILTER_PORT_MAPPING.get(dst_start) is not None:
        dst_start = FILTER_PORT_MAPPING.get(dst_start)
    entry = module.params.get('entry')
    ether_type = module.params.get('ether_type')
    filter_name = module.params.get('filter')
    icmp_msg_type = module.params.get('icmp_msg_type')
    if icmp_msg_type is not None:
        icmp_msg_type = ICMP_MAPPING.get(icmp_msg_type)
    icmp6_msg_type = module.params.get('icmp6_msg_type')
    if icmp6_msg_type is not None:
        icmp6_msg_type = ICMP6_MAPPING.get(icmp6_msg_type)
    ip_protocol = module.params.get('ip_protocol')
    state = module.params.get('state')
    stateful = aci.boolean(module.params.get('stateful'))
    tenant = module.params.get('tenant')
    name_alias = module.params.get('name_alias')

    # validate that dst_port is not passed with dst_start or dst_end
    if dst_port is not None and (dst_end is not None or dst_start is not None):
        module.fail_json(msg="Parameter 'dst_port' cannot be used with 'dst_end' and 'dst_start'")
    elif dst_port is not None:
        dst_end = dst_port
        dst_start = dst_port

    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant},
        ),
        subclass_1=dict(
            aci_class='vzFilter',
            aci_rn='flt-{0}'.format(filter_name),
            module_object=filter_name,
            target_filter={'name': filter_name},
        ),
        subclass_2=dict(
            aci_class='vzEntry',
            aci_rn='e-{0}'.format(entry),
            module_object=entry,
            target_filter={'name': entry},
        ),
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='vzEntry',
            class_config=dict(
                arpOpc=arp_flag,
                descr=description,
                dFromPort=dst_start,
                dToPort=dst_end,
                etherT=ether_type,
                icmpv4T=icmp_msg_type,
                icmpv6T=icmp6_msg_type,
                name=entry,
                prot=ip_protocol,
                stateful=stateful,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class='vzEntry')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
