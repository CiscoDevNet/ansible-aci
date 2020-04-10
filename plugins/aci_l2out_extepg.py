from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_l2out_extepg l2extInstP 
short_descrption: Manage External Network Instance object l2extInstP 
descrption: 
- Manage External Network Instance object l2extInstP 
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
  extepg:  
    descrption:
    - The Name of the external epg being creted 
       type: str
  descrption:
    descrption:
    - Name of the extepg
    type: str
  preferred_group:
    descrption:
  - It can be Exclude or Include, by default Exclude
  state:
    descrption:
    - Use pesent or absent for adding and removing
    - Use query for listing an object or multiple ojbects
    type: str
    choices: [present, absent, query]

extends_documentation_fragment: aci
note:
- The tenant, L2Out should exist befor using this module
'''



EXAMPLES = r'''

- name: Deploy New L2 external end point group 
      aci_l2out_extepg:
        host: "Host IP"
        username: admin
        password: SomeSecretePassword
        tenant: Auto-Demo
        l2out: l2out
        extepg: NewExt
        description: external epg
        preferred_group: False
        state: present
      delegate_to: localhost

- name: Remove L2 external end point group 
      aci_l2out_extepg:
        host: "Host IP"
        username: admin
        password: SomeSecretePassword
        tenant: Auto-Demo
        l2out: l2out
        extepg: NewExt
        description:
        preferred_group:
        state: absent
      delegate_to: localhost

- name: Query the L2 external end point group
      aci_l2out_extepg:
        host: "Host IP"
        username: admin
        password: SomeSecretePassword
        tenant: Auto-Demo
        l2out: l2out
        extepg: NewExt
        description:
        preferred_group:
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
           l2out=dict(type='str',aliases=['l2out_name']), 
           description=dict(type='str',aliases=['descr']),
           extepg=dict(type='str',aliases=['extepg_name']),
           preferred_group=dict(type='bool'),
           qos_class=dict(type='str', default='level3',choices=['level1','level2','level3','level4','level5','level6','Unspecified']),
           state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
           tenant=dict(type='str', aliases=['tenant_name'])
       )
   
       module = AnsibleModule(
           argument_spec=argument_spec,
          supports_check_mode=True,
          required_if=[
              ['state', 'absent', ['l2out', 'tenant', 'extepg']],
              ['state', 'present', ['l2out', 'tenant','extepg']],
          ],
       )
   
       aci = ACIModule(module)

       l2out = module.params['l2out']
       description = module.params['description']
       preferred_group = aci.boolean(module.params['preferred_group'], 'include', 'exclude')
       state = module.params['state']
       tenant = module.params['tenant']
       extepg = module.params['extepg']
       qos_class = module.params['qos_class']
          
       
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
           subclass_2=dict(
               aci_class='l2extInstP',
               aci_rn='instP-{0}'.format(extepg),
               module_object=extepg,
               target_filter={'name': extepg},

           )
         )
       
       if state == 'present':
           aci.payload(
               aci_class='l2extInstP',
               class_config=dict(
                   name=extepg,
                   descr=description,
                   dn='uni/tn-{0}/l2out-{1}/instP-{2}'.format(tenant, l2out, extepg),
                   prefGrMemb=preferred_group
               ),
               
           )
   
           aci.get_diff(aci_class='l2extInstP')
   
           aci.post_config()
   
       elif state == 'absent':
           aci.delete_config()
   
       aci.exit_json()
   
   
if __name__ == "__main__":
       main()
