#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_static_node_inb_mgmt_address:
short_descrption: In band management IP address 
descrption: 
- Define: Cisco ACI Fabric Node IP address
Version_added: 
Options:
  tenant:
    descrption:
    - Name of existing tenant.
    type: str
    aliases: [tenant_name]
  epg:
    descrption:
    - The name of the end point group
    type: str
    aliases: [epg_name]
  pod_id:
    descrption:
    - The pod number part of the tDN
    - pod_id is usually an integer 
    type: int
  node_name: 
    descrption
    - ACI Fabric node names
    type: str  
  node_id:
    descrption:
    - ACI Fabric node node_id
    type: str
  band_type:
    descrption:
    - Out of Band for Nodes
    type: str 
  ipv4_address:
    descrption:
    - ipv4 address for inb mgmt 
    type: str
  ipv4_gw:
    descrption:
    - GW address for inb mgmt
    type: str 
  ipv6_address:
    descrption:
    -  ipv6 address for inb mgmt
    type: str
  state:
    descrption:
    - Use pesent or absent for adding and removing
    - Use query for listing an object or multiple ojbects
    type: str
    choices: [present, absent, query]
extends_documentation_fragment: aci
note:
- The tenant mgmt , epg default, pood_id, node_id, node_name should exist befor using this module
'''


EXAMPLES = r'''

- name: Deploy ipv4 address to inb mgmt interface 
      aci_static_node_inb_mgmt_address:
        host: "Host IP"
        username: admin
        password: SomeSecretePassword
        tenant: mgmt
        epg: default
        pod_id: 1
        band_type: inband
        node_id: 1102
        node_name: "leaf110"
        ipv4_address: "3.1.1.2/24"
        ipv4_gw: "3.1.1.1"
        ipv6_address: 
        ipv6_gw: 
        state: present
      delegate_to: localhost

- name: Remove ipv4 address to inb mgmt interface 
      aci_static_node_inb_mgmt_address:
        host: "Host IP"
        username: admin
        password: SomeSecretePassword
        tenant: mgmt
        epg: default
        pod_id: 1
        band_type: inband
        node_id: 1102
        node_name: "leaf110"
        ipv4_address: "3.1.1.2/24"
        ipv4_gw: "3.1.1.1"
        ipv6_address: 
        ipv6_gw: 
        state: absent
      delegate_to: localhost

- name: Query the inb mgmt ipv4 address  
      aci_static_node_inb_mgmt_address:
        host: "Host IP"
        username: admin
        password: SomeSecretePassword
        tenant: mgmt
        epg: default
        pod_id: 1
        band_type: default
        node_id: 1102
        node_name: "Leaf110"
        ipv4_address: "3.1.1.2/24"
        ipv4_gw: "3.1.1.1"
        ipv6_address: 
        ipv6_gw: 
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
     sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class "/></imdata>'
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
from ansible.module_utils.network.aci.aci import ACIModule, aci_argument_spec

NODE_MAPPING = dict(
        node_path='topology/pod-{pod_id}/node-{node_id}'
        )


def main():
       argument_spec = aci_argument_spec()
       argument_spec.update(
           node_id=dict(type='str'),
           pod_id=dict(type='int'),
           node_name=dict(type='str'),  
           band_type=dict(type='str'),  
           epg=dict(type='str'),
           ipv4_address=dict(type='str'),
           ipv4_gw=dict(type='str'),
           ipv6_address=dict(type='str'),
           ipv6_gw=dict(type='str'),
           state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
           tenant=dict(type='str', aliases=['tenant_name','name'])
            )
   
       module = AnsibleModule(
           argument_spec=argument_spec,
          supports_check_mode=True,
          required_if=[
              ['state', 'absent', ['node_id', 'node_name',  'epg','ipv4_address','ipv4_gw','ipv6_address','ipv6_gw','tenant','band_type']],
              ['state', 'present', ['node_id', 'node_name',  'epg','ipv4_address','ipv4_gw','ipv6_address','ipv6_gw','tenant','band_type']],
          ],
       )
   
       node_id = module.params['node_id']
       node_name = module.params['node_name']
       band_type = module.params['band_type']
       epg = module.params['epg']
       ipv4_address = module.params['ipv4_address']
       ipv4_gw = module.params['ipv4_gw']
       ipv6_address = module.params['ipv6_address']
       ipv6_gw = module.params['ipv6_gw']
       state = module.params['state']
       tenant = module.params['tenant']
       pod_id = module.params['pod_id']
       
       
       
       static_path='topology/pod-{0}/node-{1}'.format(pod_id, node_id)
       aci = ACIModule(module)
       aci.construct_url(
           root_class=dict(
               aci_class='fvTenant',
               aci_rn='tn-{0}'.format(tenant),
               module_object=tenant,
               target_filter={'name': tenant},
           ),
           subclass_1=dict(
               aci_class='mgmtMgmtP',
               aci_rn='mgmtp-{0}'.format(epg),
               module_object=epg,
               target_filter={'name': epg},
           ),
           subclass_2=dict(
               aci_class='mgmtInB',
               aci_rn='inb-{0}'.format(band_type),
               module_object=band_type,
               target_filter={'name': band_type},
           ),
           subclass_3=dict(
               aci_class='mgmtRsInBStNode',
               aci_rn='rsinBStNode-[{0}]'.format(static_path),
               module_object=static_path,
               target_filter={'name': static_path},
           ),
       )
   
       aci.get_existing()
   
       if state == 'present':
           aci.payload(
               aci_class='mgmtRsInBStNode',
               class_config=dict(
                   addr=ipv4_address,
                   gw=ipv4_gw,
                   dn='uni/tn-{0}/mgmtp-{1}/inb-{2}/rsinBStNode-[{3}]'.format(tenant,epg,band_type,static_path),
                   v6Addr=ipv6_address,
                   v6Gw=ipv6_gw
                   
                   
               ),
           )
   
           aci.get_diff(aci_class='mgmtRsInBStNode')
   
           aci.post_config()
   
       elif state == 'absent':
           aci.delete_config()
   
       aci.exit_json()
   
   
if __name__ == "__main__":
       main()
