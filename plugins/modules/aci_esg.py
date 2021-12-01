#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_esg
short_description: Manage Endpoint Security Groups (ESGs) objects (fv:ESg)
description:
- Manage Endpoint Security Groups (ESGs) on Cisco ACI fabrics.

options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  ap:
    description:
    - Name of an existing application network profile, that will contain the ESGs.
    type: str
    aliases: [ app_profile, app_profile_name ]
  esg:
    description:
    - Name of the endpoint security group.
    type: str
    aliases: [ esg_name, name ]
  description:
    description:
    - Endpoint security group Description.
    type: str
    aliases: [ descr ]
  epg:
    description:
    - Existing endpoint group name should be in the same tenant.
    type: str
    aliases=[ epg, epg_name ]
  admin_state:
    description:
    - ESG Admin state
    type: str
    choices: [ no, yes ]
    default: no
  vrf:
    description:
    - Name of the ESG VRF
    type: str
    aliases=[ esg_vrf_name ]
  intra_esg_isolation:
    description:
    - Intra ESG Isolation
    type: str
    choices: [ enforced, unenforced ]
    default: unenforced
  preferred_group_member
    description:
    - Preferred Group Member
    type: str
    choices: [ exclude, include ]
    default: exclude
  epg_selector_description:
    description:
    - Description of the EPG selector option.
    type: str
  match_key:
    description:
    - ESG Tag Selector Key Name
    type: str
    aliases=[ esg_match_key ]
  value_operator:
    description:
    - ESG Tag Selector operator type
    type: str
    default: equals
    choices=[ contains , equals, regex ]
    aliases=[ esg_value_operator ]
  match_value:
    description:
    - ESG Tag Selector Key Value
    type: str
    aliases=[ esg_match_value ]
  tag_selector_description:
    description:
    - Description of the ESG Tag Selector.
    type: str
    aliases=[ esg_tag_selector_description ]
  subnet_ip:
    description:
    - ESG Subnet IP
    type: str
    aliases=[ esg_subnet_ip ]
  subnet_selector_description:
    description:
    - Description of the ESG Subnet Selector option.
    type: str
    aliases=[ esg_subnet_selector_description ]
  esg_contract_master:
    description:
    - Existing ESG name under the same Application profile
    type: str
    aliases=[ esg_contract_master ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    default: present
    choices: [ absent, present, query ]
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
extends_documentation_fragment:
- cisco.aci.aci

seealso:
- module: cisco.aci.aci_aep_to_domain
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(infra:AttEntityP) and B(infra:ProvAcc).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sabari Jaganathan (@sajagana)
'''
ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'certified',
}


EXAMPLES = r'''
- name: Add a new ESG
  cisco.aci.aci_esg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    ap: intranet
    esg: web_esg
    vrf: 'default'
    description: Web Intranet ESG
    state: present
  delegate_to: localhost

- name: Add list of ESGs
  cisco.aci.aci_esg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    ap: ticketing
    esg: "{{ item.esg }}"
    description: Ticketing ESG
    vrf: 'default'
    state: present
  delegate_to: localhost
  with_items:
    - esg: web
    - esg: database

- name: Query an ESG
  cisco.aci.aci_esg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    ap: ticketing
    esg: web_esg
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all ESGs
  cisco.aci.aci_esg:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all ESGs with a Specific Name
  cisco.aci.aci_esg:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: no
    esg: web_esg
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all ESGs of an App Profile
  cisco.aci.aci_esg:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: no
    ap: ticketing
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove an ESG
  cisco.aci.aci_esg:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: no
    tenant: production
    app_profile: intranet
    esg: web_esg
    vrf: default
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        tenant=dict(type='str', aliases=['tenant_name']),
        ap=dict(type='str', aliases=['app_profile', 'app_profile_name']),
        esg=dict(type='str', aliases=['name', 'esg_name']),
        description=dict(type='str', aliases=['descr']),
        epg=dict(type='str', aliases=['epg', 'epg_name']),
        admin_state=dict(type='str', default='no', choices=['no', 'yes']),  # ESG Admin State
        vrf=dict(type='str', aliases=['esg_vrf_name']),  # ESG VRF name
        intra_esg_isolation=dict(
            type='str',
            default='unenforced',
            choices=['enforced', 'unenforced'],
        ),  # Intra ESG Isolation
        preferred_group_member=dict(type='str', default='exclude', choices=['exclude', 'include']),  # Preferred Group Member
        epg_selector_description=dict(type='str', aliases=['epg_selector_description']),
        match_key=dict(type='str', aliases=['esg_match_key']),  # ESG Tag Selector Key Name
        value_operator=dict(
            type='str', default='equals', choices=['contains', 'equals', 'regex'], aliases=['esg_value_operator']
        ),  # ESG Tag Selector Operator type
        match_value=dict(type='str', aliases=['esg_match_value']),  # ESG Tag Selector Key Value
        tag_selector_description=dict(type='str', aliases=['esg_tag_selector_description']),
        subnet_ip=dict(type='str', aliases=['esg_subnet_ip']),  # ESG Subnet IP
        subnet_selector_description=dict(type='str', aliases=['esg_subnet_selector_description']),
        esg_contract_master=dict(type='str', aliases=['esg_contract_master']),  # Contract Master name for ESG
        state=dict(
            type='str',
            default='present',
            choices=['absent', 'present', 'query'],
        ),
        name_alias=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['tenant', 'ap', 'esg', 'vrf']],
            ['state', 'present', ['tenant', 'ap', 'esg', 'vrf']],
        ],
        required_together=[['match_key', 'match_value']],
    )

    aci = ACIModule(module)
    tenant = module.params.get('tenant')
    ap = module.params.get('ap')
    esg = module.params.get('esg')
    description = module.params.get('description')
    epg = module.params.get('epg')
    admin_state = module.params.get('admin_state')
    vrf = module.params.get('vrf')
    intra_esg_isolation = module.params.get('intra_esg_isolation')
    preferred_group_member = module.params.get('preferred_group_member')
    state = module.params.get('state')
    name_alias = module.params.get('name_alias')
    epg_selector_description = module.params.get('epg_selector_description')
    esg_contract_master = module.params.get('esg_contract_master')
    value_operator = module.params.get('value_operator')
    match_key = module.params.get('match_key')
    match_value = module.params.get('match_value')
    tag_selector_description = module.params.get('tag_selector_description')
    subnet_selector_description = module.params.get('subnet_selector_description')
    subnet_ip = module.params.get('subnet_ip')

    # VRF Selection - fvRsScope
    child_configs = [dict(fvRsScope=dict(attributes=dict(tnFvCtxName=vrf)))]

    # Tag Selector - fvTagSelector
    if None not in (match_key, match_value) and '' not in (match_key, match_value):
        child_configs.append(
            dict(
                fvTagSelector=dict(
                    attributes=dict(
                        matchKey=match_key,
                        matchValue=match_value,
                        valueOperator=value_operator,
                        descr=tag_selector_description,
                    )
                )
            )
        )

    # EPG Selector - fvEPgSelector
    if epg is not None:
        child_configs.append(
            dict(
                fvEPgSelector=dict(
                    attributes=dict(
                        matchEpgDn="uni/tn-{0}/ap-{1}/epg-{2}".format(tenant, ap, epg),
                        descr=epg_selector_description,
                    )
                )
            )
        )

    # IP Subnet Selector - fvEPSelector
    if subnet_ip is not None:
        child_configs.append(
            dict(
                fvEPSelector=dict(
                    attributes=dict(
                        matchExpression="ip=='{0}'".format(subnet_ip),
                        descr=subnet_selector_description,
                    )
                )
            )
        )

    # ESG Contract Master - fvRsSecInherited
    if esg_contract_master is not None:
        tDn = "uni/tn-{0}/ap-{1}/esg-{2}".format(tenant, ap, esg_contract_master)
        child_configs.append(dict(fvRsSecInherited=dict(attributes=dict(tDn=tDn))))

    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant},
        ),
        subclass_1=dict(
            aci_class='fvAp',
            aci_rn='ap-{0}'.format(ap),
            module_object=ap,
            target_filter={'name': ap},
        ),
        subclass_2=dict(
            aci_class='fvESg',
            aci_rn='esg-{0}'.format(esg),
            module_object=esg,
            target_filter={'name': esg},
        ),
        child_classes=[
            'fvRsScope',
            'fvTagSelector',
            'fvEPgSelector',
            'fvEPSelector',
            'fvRsSecInherited',
        ],
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='fvESg',
            class_config=dict(
                name=esg,
                descr=description,
                shutdown=admin_state,
                pcEnfPref=intra_esg_isolation,
                prefGrMemb=preferred_group_member,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class='fvESg')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
