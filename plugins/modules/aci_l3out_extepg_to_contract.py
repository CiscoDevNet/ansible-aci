#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, fn ln (@kudtarkar1) <@.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: aci_l3out_extepg_to_contract:
short_descrption: Bind External End Point Groups to Contracts 
descrption: 
- Bind ExtEPGs to Contracts on ACI fabrics.
Version_added: 
Options:
  tenant:
    descrption:
    - Name of existing tenant.
    type: str
    aliases: [tenant_name]
  l3Out:
    descrption:
    - The name of the L3Outs
    type: str
    aliases: [l3out_name]
  extepg:
    descrption:
    - The name of the external end point groups
    type: str
    aliases: [extepg_name]
  contract:
    descrption:
    - The name of the contract
    type: str
  contract_type:
    descrption:
    - The type of contract(provider or consumer)
  state:
    descrption:
    - Use pesent or absent for adding and removing
    - Use query for listing an object or multiple ojbects
    type: str
    choices: [present, absent, query]
extends_documentation_fragment: aci
note:
- The tenant, l3Out, extepg, contract should exist before using this module
'''

EXAMPLES = r'''
- name: Bind External End Point Groups to Contracts 
  cisco.aci.aci_l3out_epg_to_contract:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: Auto-Demo
    l3Out: l3out
    extepg : testEpg
    contract: contract1
    contract_type: provider
    state: present
  delegate_to: localhost

- name: Remove existing contract to External End Point Groups
  cisco.aco.aci_l3out_epg_to_contract:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: Auto-Demo
    l3Out: l3out
    extepg : testEpg
    contract: contract1
    contract_type: provider
    state: absent
  delegate_to: localhost
        
- name: Query the OOB mgmt ipv4 address  
  cisco.aci.aci_l3out_epg_to_contract:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: Auto-Demo
    l3Out: l3out
    extepg : testEpg
    contract: contract1
    contract_type: provider
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

ACI_CLASS_MAPPING = dict(
       consumer={
           'class': 'fvRsCons',
           'rn': 'rscons-',
       },
       provider={
           'class': 'fvRsProv',
           'rn': 'rsprov-',
       },
)

PROVIDER_MATCH_MAPPING = dict(
       all='All',
       at_least_one='AtleastOne',
       at_most_one='tmostOne',
       none='None',
)

def main():
       argument_spec = aci_argument_spec()
       argument_spec.update(
           contract_type=dict(type='str', required=True, choices=['consumer', 'provider']),
           l3Out=dict(type='str', aliases=['l3Out_name']), 
           contract=dict(type='str', aliases=['contract_name']),  
           priority=dict(type='str', choices=['level1', 'level2', 'level3', 'unspecified']),
           provider_match=dict(type='str', choices=['all', 'at_least_one', 'at_most_one', 'none']),
           state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
           tenant=dict(type='str', aliases=['tenant_name']),
           extepg=dict(type='str',aliases=['externalEpg_name'])  
        )

       module = AnsibleModule(
          argument_spec=argument_spec,
          supports_check_mode=True,
          required_if=[
              ['state', 'absent', ['extepg', 'contract', 'l3Out', 'tenant']],
              ['state', 'present', ['extepg', 'contract', 'l3Out', 'tenant']],
          ],
        )

       l3Out = module.params['l3Out']
       contract = module.params['contract']
       contract_type = module.params['contract_type']
       extepg = module.params['extepg']
       priority = module.params['priority']
       provider_match = module.params['provider_match']
       if provider_match is not None:
           provider_match = PROVIDER_MATCH_MAPPING[provider_match]
       state = module.params['state']
       tenant = module.params['tenant']

       aci_class = ACI_CLASS_MAPPING[contract_type]["class"]
       aci_rn = ACI_CLASS_MAPPING[contract_type]["rn"]

       if contract_type == "consumer" and provider_match is not None:
           module.fail_json(msg="the 'provider_match' is only configurable for Provided Contracts")

       aci = ACIModule(module)

       aci.construct_url(
           root_class=dict(
               aci_class='fvTenant',
               aci_rn='tn-{0}'.format(tenant),
               module_object=tenant,
               target_filter={'name': tenant},
           ),
           subclass_1=dict(
               aci_class='l3extOut',
               aci_rn='out-{0}'.format(l3Out),
               module_object=l3Out,
               target_filter={'name': l3Out},
           ),
           subclass_2=dict(
               aci_class='l3extInstP',
               aci_rn='instP-{0}'.format(extepg),
               module_object=extepg,
               target_filter={'name': extepg},
           ),
           subclass_3=dict(
               aci_class=aci_class,
               aci_rn='{0}{1}'.format(aci_rn, contract),
               module_object=contract,
               target_filter={'tnVzBrCPName': contract},
           ),
       )

       aci.get_existing()

       if state == 'present':
           aci.payload(
               aci_class=aci_class,
               class_config=dict(
                   matchT=provider_match,
                   prio=priority,
                   tnVzBrCPName=contract,
               ),
           )

           aci.get_diff(aci_class=aci_class)

           aci.post_config()

       elif state == 'absent':
           aci.delete_config()

       aci.exit_json()


if __name__ == "__main__":
       main()
