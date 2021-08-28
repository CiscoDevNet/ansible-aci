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
module: aci_l3out_bgp_peer
short_description: Manage Layer 3 Outside (L3Out) BGP Peers (bgp:PeerP)
description:
- Manage L3Out BGP Peers on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
    required: yes
  l3out:
    description:
    - Name of an existing L3Out.
    type: str
    aliases: [ l3out_name ]
    required: yes
  node_profile:
    description:
    - Name of the node profile.
    type: str
    aliases: [ node_profile_name, logical_node ]
    required: yes
  interface_profile:
    description:
    - Name of the interface profile.
    type: str
    aliases: [ interface_profile_name, logical_interface ]
    required: yes
  pod_id:
    description:
    - Pod to build the interface on.
    type: str
    required: yes
  node_id:
    description:
    - Node to build the interface on for Port-channels and single ports.
    - Hyphen separated pair of nodes (e.g. "201-202") for vPCs.
    type: str
    required: yes
  path_ep:
    description:
    - Path to interface
    - Interface Port Group name for Port-channels and vPCs
    - Port number for single ports (e.g. "eth1/12")
    type: str
    required: yes
  peer_ip:
    description:
    - IP address of the BGP peer.
    type: str
    required: yes
  remote_asn:
    description:
    - Autonomous System Number of the BGP peer.
    type: int
  bgp_controls:
    description:
    - BGP Controls
    type: list
    elements: str
    choices: [ send-com, send-ext-com, allow-self-as, as-override, dis-peer-as-check, nh-self ]
  peer_controls:
    description:
    - Peer Controls
    type: list
    elements: str
    choices: [ bfd, dis-conn-check ]
  address_type_controls:
    description:
    - Address Type Controls
    type: list
    elements: str
    choices: [ af-ucast, af-mcast ]
  private_asn_controls:
    description:
    - Private AS Controls
    type: list
    elements: str
    choices: [ remove-exclusive, remove-all, replace-as ]
  ttl:
    description:
    - eBGP Multihop Time To Live
    type: int
  weight:
    description:
    - Weight for BGP routes from this neighbor
    type: int
  admin_state:
    description:
    - Admin state for the BGP session
    type: str
    choices: [ enabled, disabled ]
  allow_self_as_count:
    description:
    - Number of allowed self AS.
    - Only used if C(allow-self-as) is enabled under C(bgp_controls).
    type: int
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci

seealso:
- module: aci_l3out
- module: aci_l3out_logical_node_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(bgp:peerP)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
'''

EXAMPLES = r'''
- name: Add a new BGP peer on a physical interface
  cisco.aci.aci_l3out_bgp_peer:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    path_ep: eth1/12
    peer_ip: 192.168.10.2
    remote_asn: 65456
    bgp_controls:
      - nh-self
      - send-com
      - send-ext-com
    peer_controls:
      - bfd
    state: present
  delegate_to: localhost

- name: Add a new BGP peer on a vPC
  cisco.aci.aci_l3out_bgp_peer:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201-202
    path_ep: my_vpc_ipg
    peer_ip: 192.168.20.2
    remote_asn: 65457
    ttl: 4
    weight: 50
    state: present
  delegate_to: localhost

- name: Shutdown a BGP peer
  cisco.aci.aci_l3out_bgp_peer:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    path_ep: eth1/12
    peer_ip: 192.168.10.2
    admin_state: disabled
    state: present
  delegate_to: localhost

- name: Delete a BGP peer
  cisco.aci.aci_l3out_bgp_peer:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    path_ep: eth1/12
    peer_ip: 192.168.10.2
    state: absent
  delegate_to: localhost

- name: Query a BGP peer
  cisco.aci.aci_l3out_bgp_peer:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    path_ep: eth1/12
    peer_ip: 192.168.10.2
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
        tenant=dict(type='str', aliases=['tenant_name'], required=True),
        l3out=dict(type='str', aliases=['l3out_name'], required=True),
        node_profile=dict(type='str', aliases=[
                          'node_profile_name', 'logical_node'], required=True),
        interface_profile=dict(type='str', aliases=[
            'interface_profile_name', 'logical_interface'], required=True),
        state=dict(type='str', default='present',
                   choices=['absent', 'present', 'query']),
        pod_id=dict(type='str', required=True),
        node_id=dict(type='str', required=True),
        path_ep=dict(type='str', required=True),
        peer_ip=dict(type='str', required=True),
        remote_asn=dict(type='int'),
        bgp_controls=dict(type='list', elements='str',
                          choices=['send-com', 'send-ext-com', 'allow-self-as',
                                   'as-override', 'dis-peer-as-check',
                                   'nh-self']),
        peer_controls=dict(type='list', elements='str',
                           choices=['bfd', 'dis-conn-check']),
        address_type_controls=dict(type='list', elements='str',
                                   choices=['af-ucast', 'af-mcast']),
        private_asn_controls=dict(type='list', elements='str',
                                  choices=['remove-exclusive',
                                           'remove-all',
                                           'replace-as']),
        ttl=dict(type='int'),
        weight=dict(type='int'),
        admin_state=dict(type='str', choices=['enabled', 'disabled']),
        allow_self_as_count=dict(type='int'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    tenant = module.params.get('tenant')
    l3out = module.params.get('l3out')
    node_profile = module.params.get('node_profile')
    interface_profile = module.params.get('interface_profile')
    state = module.params.get('state')
    pod_id = module.params.get('pod_id')
    node_id = module.params.get('node_id')
    path_ep = module.params.get('path_ep')
    peer_ip = module.params.get('peer_ip')
    remote_asn = module.params.get('remote_asn')
    bgp_controls = module.params.get('bgp_controls')
    peer_controls = module.params.get('peer_controls')
    address_type_controls = module.params.get('address_type_controls')
    private_asn_controls = module.params.get('private_asn_controls')
    ttl = module.params.get('ttl')
    weight = module.params.get('weight')
    admin_state = module.params.get('admin_state')
    allow_self_as_count = module.params.get('allow_self_as_count')

    aci = ACIModule(module)
    if '-' in node_id:
        path_type = 'protpaths'
    else:
        path_type = 'paths'

    path_dn = ('topology/pod-{0}/{1}-{2}/pathep-[{3}]'.format(pod_id,
                                                              path_type,
                                                              node_id,
                                                              path_ep))

    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant},
        ),
        subclass_1=dict(
            aci_class='l3extOut',
            aci_rn='out-{0}'.format(l3out),
            module_object=l3out,
            target_filter={'name': l3out},
        ),
        subclass_2=dict(
            aci_class='l3extLNodeP',
            aci_rn='lnodep-{0}'.format(node_profile),
            module_object=node_profile,
            target_filter={'name': node_profile},
        ),
        subclass_3=dict(
            aci_class='l3extLIfP',
            aci_rn='lifp-{0}'.format(interface_profile),
            module_object=interface_profile,
            target_filter={'name': interface_profile},
        ),
        subclass_4=dict(
            aci_class='l3extRsPathL3OutAtt',
            aci_rn='/rspathL3OutAtt-[{0}]'.format(path_dn),
            module_object=path_dn,
            target_filter={'tDn': path_dn}
        ),
        subclass_5=dict(
            aci_class='bgpPeerP',
            aci_rn='/peerP-[{0}]'.format(peer_ip),
            module_object=peer_ip,
            target_filter={'addr': peer_ip}
        ),
        child_classes=['bgpRsPeerPfxPol', 'bgpAsP', 'bgpLocalAsnP']
    )

    aci.get_existing()

    if state == 'present':
        ctrl, peerCtrl, addrTCtrl, privateASctrl = None, None, None, None
        if bgp_controls:
            ctrl = ','.join(bgp_controls)
        if peer_controls:
            peerCtrl = ','.join(peer_controls)
        if address_type_controls:
            addrTCtrl = ','.join(address_type_controls)
        if private_asn_controls:
            privateASctrl = ','.join(private_asn_controls)
        aci.payload(
            aci_class='bgpPeerP',
            class_config=dict(
                addr=peer_ip,
                ctrl=ctrl,
                peerCtrl=peerCtrl,
                addrTCtrl=addrTCtrl,
                privateASctrl=privateASctrl,
                ttl=ttl,
                weight=weight,
                adminSt=admin_state,
                allowedSelfAsCnt=allow_self_as_count
            ),
            child_configs=[
                dict(
                    bgpAsP=dict(
                        attributes=dict(
                            asn=remote_asn
                        ),
                    ),
                ),
            ],
        )

        aci.get_diff(aci_class='bgpPeerP')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
