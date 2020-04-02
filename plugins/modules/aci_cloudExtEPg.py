#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloudExtEPg 
short_description: Manage Cloud External EPg (cloud:ExtEPg)
description:
- Mo doc not defined in techpub!!!
notes:
- More information about the internal APIC class B(cloud:ExtEPg) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Devarshi Shah (@devarshishah3)
version_added: '2.7'
options: 
  annotation:
    description:
    - Mo doc not defined in techpub!!! 
  descr:
    description:
    - configuration item description. 
  exceptionTag:
    description:
    - Mo doc not defined in techpub!!! 
  floodOnEncap:
    description:
    - Mo doc not defined in techpub!!! 
    choices: [ disabled, enabled ] 
  matchT:
    description:
    - match criteria 
    choices: [ All, AtleastOne, AtmostOne, None ] 
  name:
    description:
    - object name 
    aliases: [ cloud_external_epg ] 
  nameAlias:
    description:
    - Mo doc not defined in techpub!!! 
  prefGrMemb:
    description:
    - Mo doc not defined in techpub!!! 
    choices: [ exclude, include ] 
  prio:
    description:
    - qos priority class id 
    choices: [ level1, level2, level3, level4, level5, level6, unspecified ] 
  routeReachability:
    description:
    - Mo doc not defined in techpub!!! 
    choices: [ inter-site, internet, unspecified ] 
  tenant:
    description:
    - tenant name 
  cloud_application_container:
    description:
    - object name 
  state: 
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    choices: [ absent, present, query ]
    default: present 

extends_documentation_fragment: aci
'''

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
from ansible.module_utils.basic import AnsibleModule

def main():
    argument_spec = aci_argument_spec()
    argument_spec.update({ 
        'annotation': dict(type='str',),
        'descr': dict(type='str',),
        'exceptionTag': dict(type='str',),
        'floodOnEncap': dict(type='str', choices=['disabled', 'enabled'], ),
        'matchT': dict(type='str', choices=['All', 'AtleastOne', 'AtmostOne', 'None'], ),
        'name': dict(type='str', aliases=['cloud_external_epg']),
        'nameAlias': dict(type='str',),
        'prefGrMemb': dict(type='str', choices=['exclude', 'include'], ),
        'prio': dict(type='str', choices=['level1', 'level2', 'level3', 'level4', 'level5', 'level6', 'unspecified'], ),
        'routeReachability': dict(type='str', choices=['inter-site', 'internet', 'unspecified'], ),
        'tenant': dict(type='str',),
        'cloud_application_container': dict(type='str',),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),

        'relation_fv_rs_sec_inherited': dict(type='list'),

        'relation_fv_rs_prov': dict(type='list'),

        'relation_fv_rs_cons_if': dict(type='list'),

        'relation_fv_rs_cust_qos_pol': dict(type='str'),

        'relation_fv_rs_cons': dict(type='list'),

        'relation_cloud_rs_cloud_e_pg_ctx': dict(type='str'),

        'relation_fv_rs_prot_by': dict(type='list'),

        'relation_fv_rs_intra_epg': dict(type='list'),

    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', ['name', 'tenant', 'cloud_application_container', ]], 
            ['state', 'present', ['name', 'tenant', 'cloud_application_container', ]],
        ],
    )
    
    annotation = module.params['annotation']
    descr = module.params['descr']
    exceptionTag = module.params['exceptionTag']
    floodOnEncap = module.params['floodOnEncap']
    matchT = module.params['matchT']
    name = module.params['name']
    nameAlias = module.params['nameAlias']
    prefGrMemb = module.params['prefGrMemb']
    prio = module.params['prio']
    routeReachability = module.params['routeReachability']
    tenant = module.params['tenant']
    cloud_application_container = module.params['cloud_application_container']
    state = module.params['state']
    child_configs=[]
    
    relation_fvrssecinherited = module.params['relation_fv_rs_sec_inherited']
    relation_fvrsprov = module.params['relation_fv_rs_prov']
    relation_fvrsconsif = module.params['relation_fv_rs_cons_if']
    relation_fvrscustqospol = module.params['relation_fv_rs_cust_qos_pol']
    relation_fvrscons = module.params['relation_fv_rs_cons']
    relation_cloudrscloudepgctx = module.params['relation_cloud_rs_cloud_e_pg_ctx']
    relation_fvrsprotby = module.params['relation_fv_rs_prot_by']
    relation_fvrsintraepg = module.params['relation_fv_rs_intra_epg']

    if relation_fvrssecinherited:
        for relation_param in relation_fvrssecinherited:
            child_configs.append({'fvRsSecInherited': {'attributes': {'tDn': relation_param}}})

    if relation_fvrsprov:
        for relation_param in relation_fvrsprov:
            child_configs.append({'fvRsProv': {'attributes': {'tnVzBrCPName': relation_param}}})

    if relation_fvrsconsif:
        for relation_param in relation_fvrsconsif:
            child_configs.append({'fvRsConsIf': {'attributes': {'tnVzCPIfName': relation_param}}})
    if relation_fvrscustqospol:
        child_configs.append({'fvRsCustQosPol': {'attributes': {'tnQosCustomPolName': relation_fvrscustqospol}}})

    if relation_fvrscons:
        for relation_param in relation_fvrscons:
            child_configs.append({'fvRsCons': {'attributes': {'tnVzBrCPName': relation_param}}})
    if relation_cloudrscloudepgctx:
        child_configs.append({'cloudRsCloudEPgCtx': {'attributes': {'tnFvCtxName': relation_cloudrscloudepgctx}}})

    if relation_fvrsprotby:
        for relation_param in relation_fvrsprotby:
            child_configs.append({'fvRsProtBy': {'attributes': {'tnVzTabooName': relation_param}}})

    if relation_fvrsintraepg:
        for relation_param in relation_fvrsintraepg:
            child_configs.append({'fvRsIntraEpg': {'attributes': {'tnVzBrCPName': relation_param}}})

    aci = ACIModule(module)
    aci.construct_url(
        root_class={
            'aci_class': 'fvTenant',
            'aci_rn': 'tn-{}'.format(tenant),
            'target_filter': 'eq(fvTenant.name, "{}")'.format(tenant),
            'module_object': tenant
        }, 
        subclass_1={
            'aci_class': 'cloudApp',
            'aci_rn': 'cloudapp-{}'.format(cloud_application_container),
            'target_filter': 'eq(cloudApp.name, "{}")'.format(cloud_application_container),
            'module_object': cloud_application_container
        }, 
        subclass_2={
            'aci_class': 'cloudExtEPg',
            'aci_rn': 'cloudextepg-{}'.format(name),
            'target_filter': 'eq(cloudExtEPg.name, "{}")'.format(name),
            'module_object': name
        }, 
        
        child_classes=['fvRsSecInherited','fvRsProv','fvRsConsIf','fvRsCustQosPol','fvRsCons','cloudRsCloudEPgCtx','fvRsProtBy','fvRsIntraEpg']
        
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudExtEPg',
            class_config={ 
                'annotation': annotation,
                'descr': descr,
                'exceptionTag': exceptionTag,
                'floodOnEncap': floodOnEncap,
                'matchT': matchT,
                'name': name,
                'nameAlias': nameAlias,
                'prefGrMemb': prefGrMemb,
                'prio': prio,
                'routeReachability': routeReachability,
            },
            child_configs=child_configs
           
        )

        aci.get_diff(aci_class='cloudExtEPg')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()