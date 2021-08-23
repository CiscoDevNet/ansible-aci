#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Cindy Zhao <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloud_epg_selector 
short_description: Manage Cloud Endpoint Selector (cloud:EPSelector)
description:
- Manage Cloud Endpoint Selector on Cisco Cloud ACI
notes:
- More information about the internal APIC class B(cloud:EPSelector) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Nirav (@nirav)
- Cindy Zhao (@cizhao)
options:
  description:
    description:
    - Description of the Cloud Endpoint Selector.
    type: str
  expressions:
    description:
    - Expressions associated to this selector.
    type: list
    elements: dict
    suboptions:
      key:
        description:
        - The key of the expression.
        - The key is custom or is one of region, zone and ip
        - The key can be zone only when the site is AWS.
        required: true
        type: str
      operator:
        description:
        - The operator associated to the expression.
        - Operator has_key or does_not_have_key is only available for key custom or zone
        required: true
        type: str
        choices: [ not_in, in, equals, not_equals, has_key, does_not_have_key ]
      value:
        description:
        - The value associated to the expression.
        - If the operator is in or not_in, the value should be a comma separated string.
        type: str
  name:
    description:
    - The name of the Cloud Endpoint selector.
    aliases: [ selector ]
    type: str
  tenant:
    description:
    - The name of the existing tenant.
    required: yes
    type: str
  ap:
    description:
    - The name of the cloud application profile.
    required: yes
    type: str
  epg:
    description:
    - The name of the cloud EPG.
    required: yes
    type: str
  cloud_type:
    description:
    - The type of the cloud Apic.
    type: str
    choices: [ aws, azure ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    choices: [ absent, present, query ]
    default: present 
    type: str

extends_documentation_fragment:
- cisco.aci.aci
'''

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, expression_spec
from ansible.module_utils.basic import AnsibleModule

EXPRESSION_KEYS = {
    'ip': 'IP',
    'region': 'Region',
    'zone': 'Zone',
}

EXPRESSION_OPERATORS = {
    'not_in': 'notin',
    'not_equals': '!=',
    'in': 'in',
    'equals': '==',
}


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update({ 
        'description': dict(type='str'),
        'expressions': dict(type='list', elements='dict', options=expression_spec()),
        'name': dict(type='str', aliases=['selector']),
        'tenant': dict(type='str', required=True),
        'ap': dict(type='str', required=True),
        'epg': dict(type='str', required=True),
        'cloud_type': dict(type='str', choices=['aws', 'azure']),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),
    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[ 
            ['state', 'absent', ['name']], 
            ['state', 'present', ['name', 'cloud_type']],
        ],
    )

    description = module.params['description']
    expressions = module.params['expressions']
    name = module.params['name']
    tenant = module.params['tenant']
    ap = module.params['ap']
    epg = module.params['epg']
    cloud_type = module.params['cloud_type']
    state = module.params['state']
    child_configs=[]


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
            'aci_rn': 'cloudapp-{}'.format(ap),
            'target_filter': 'eq(cloudApp.name, "{}")'.format(ap),
            'module_object': ap
        }, 
        subclass_2={
            'aci_class': 'cloudEPg',
            'aci_rn': 'cloudepg-{}'.format(epg),
            'target_filter': 'eq(cloudEPg.name, "{}")'.format(epg),
            'module_object': epg
        }, 
        subclass_3={
            'aci_class': 'cloudEPSelector',
            'aci_rn': 'epselector-{}'.format(name),
            'target_filter': 'eq(cloudEPSelector.name, "{}")'.format(name),
            'module_object': name
        }, 
        
        child_classes=[]
        
    )

    aci.get_existing()

    if state == 'present':
        expressions_list = []
        for expression in expressions:
            key = expression.get('key')
            operator = expression.get('operator')
            if expression.get('value'):
                value = "'" + "','".join(expression.get('value').split( "," )) + "'"
            else:
                value = None
            if operator in ["has_key", "does_not_have_key"]:
                if value:
                    module.fail_json(
                        msg="Attribute 'value' is not supported for operator '{0}' in expression '{1}'".format(operator, key))
                if key in ["ip", "region"]:
                    module.fail_json(msg="Operator '{0}' is not supported when expression key is '{1}'".format(operator, key))
            if operator in ["not_in", "in", "equals", "not_equals"] and not value:
                module.fail_json(
                    msg="Attribute 'value' needed for operator '{0}' in expression '{1}'".format(operator, key))
            if key == "zone" and cloud_type is not "aws":
                module.fail_json(
                    msg="Key '{0}' is only supported for AWS cloud".format(key))
            if key in ["ip", "region","zone"]:
                key = EXPRESSION_KEYS.get(key)
            else:
                key = 'custom:' + key
            if operator in ["not_in", "in"]:
                expressions_list.append('{0} {1}({2})'.format(key, EXPRESSION_OPERATORS.get(operator), value))
            elif operator in ["equals", "not_equals"]:
                expressions_list.append('{0}{1}{2}'.format(key, EXPRESSION_OPERATORS.get(operator), value))
            elif operator == "does_not_have_key":
                expressions_list.append('!{0}'.format(key))
            else:
                expressions_list.append(key)
        matchExpression = ','.join(expressions_list)
        aci.payload(
            aci_class='cloudEPSelector',
            class_config={ 
                'descr': description,
                'matchExpression': matchExpression,
                'name': name,
            },
            child_configs=child_configs
        )

        aci.get_diff(aci_class='cloudEPSelector')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()

if __name__ == "__main__":
    main()