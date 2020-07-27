from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: aci_l2out
short_descrption: Manage layer 2 outside(L2Out) objects 
descrption: 
- Manage layer 2 Outside on Cisco ACI fabric.
Version_added: 
Options:
  tenant:
    descrption:
    - Name of existing tenant.
    type: str
    aliases: [tenant_name]
  l2out:
    descrption:
    - The name of the Layer 2 Outside
    type: str
  descrption:
    descrption:
    - The descrption of the Layer 2 Outside
       type: str
  bd: 
    descrption
    - Name of the Bridge domain which is associted to L2Out 
    type: str
  Domain:
    descrption:
    - Name of the external L2 Domain being associated with L2Out
    type: str
 
  vlan:
    descrption:
    - Vlan which being associated to L2
    type: str 
     
  state:
    descrption:
    - Use pesent or absent for adding and removing
    - Use query for listing an object or multiple ojbects
    type: str
    choices: [present, absent, query]
extends_documentation_fragment: aci
note:
- The tenant , L2 external Bridged Domain, Bridge Domain should exist befor using this module
'''



EXAMPLES = r'''
- name: Deploy New L2Out 
      aci_l2out:
        host: "Host IP"
        username: admin
        password: SomeSecretePassword
        tenant: Auto-Demo
        l2out: l2out
        description: 
        bd: bd1
        domain: l2Dom
        vlan: vlan-3200
        state: present
      delegate_to: localhost
- name: Remove L2Out 
      aci_static_node_oob_mgmt_address:
        host: "Host IP"
        username: admin
        password: SomeSecretePassword
        tenant: Auto-Demo
        l2out: l2out
        description: 
        bd: 
        domain: 
        vlan: 
        state: absent
      delegate_to: localhost
- name: Query the L2Out  
      aci_static_node_oob_mgmt_address:
        host: "Host IP"
        username: admin
        password: SomeSecretePassword
        tenant: Auto-Demo
        l2out: l2out
        description: 
        bd: bd1
        domain: l2Dom
        vlan: vlan-3200
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

def main():
       argument_spec = aci_argument_spec()
       argument_spec.update(
           bd=dict(type='str'),
           l2out=dict(type='str',aliases=['l2out_name']), 
           domain=dict(type='str'),
           vlan=dict(type='str'),
           description=dict(type='str',aliases=['description_name']),
           targetDscp=dict(type='str'),
           state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
           tenant=dict(type='str', aliases=['tenant_name'])
       )

       module = AnsibleModule(
           argument_spec=argument_spec,
          supports_check_mode=True,
          required_if=[
              ['state', 'absent', ['bd', 'l2out', 'tenant', 'domain', 'vlan']],
              ['state', 'present', ['bd', 'l2out', 'tenant', 'domain', 'vlan']],
          ],
       )

       bd = module.params['bd']
       l2out = module.params['l2out']
       description = module.params['description']
       domain = module.params['domain']
       vlan = module.params['vlan']
       state = module.params['state']
       tenant = module.params['tenant']
       targetDscp = module.params ['targetDscp']
       child_classes = ['l2extRsEBd', 'l2extRsL2DomAtt', 'l2extLNodeP']

       aci = ACIModule(module)
       aci.construct_url(
           root_class=dict(
               aci_class='fvTenant',
               aci_rn='tn-{0}'.format(tenant),
               module_object=tenant,
               target_filter={'name': tenant},
           ),
           subclass_1=dict(
               aci_class='l2extOut',
               aci_rn='l2out-{0}'.format(l2out),
               module_object=l2out,
               target_filter={'name': l2out},
           ),
           child_classes=child_classes,
        )

       aci.get_existing()
       child_configs=[
           dict(l2extRsL2DomAtt=dict(attributes=dict(
            tDn='uni/l2dom-{0}'.format(domain)))),
           dict(l2extRsEBd=dict(attributes=dict(
            tnFvBDName=bd,encap=vlan)))
       ]

       if state == 'present':
           aci.payload(
               aci_class='l2extOut',
               class_config=dict(
                   name=l2out,
                   descr=description,
                   dn='uni/tn-{0}/l2out-{1}'.format(tenant, l2out),
                   targetDscp=targetDscp 
               ),
               child_configs=child_configs,
           )

           aci.get_diff(aci_class='l2extOut')

           aci.post_config()

       elif state == 'absent':
           aci.delete_config()

       aci.exit_json()


if __name__ == "__main__":
       main()