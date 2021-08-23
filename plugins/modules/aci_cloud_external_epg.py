#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloud_external_epg
short_description: Manage Cloud External EPg (cloud:ExtEPg)
description:
- Configures WAN router connectivity to the cloud infrastructure.
notes:
- More information about the internal APIC class B(cloud:ExtEPg) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Devarshi Shah (@devarshishah3)
- Anvitha Jain (@anvitha-jain)
version_added: '2.7'
options:
  description:
    description:
    - configuration item description.
    type: str
  exception_tag:
    description:
    - Control at EPG level if the traffic L2 Multicast/Broadcast and Link Local Layer should be flooded only on ENCAP
    - or based on bridge-domain settings.
    type: str
  flood_on_encap:
    description:
    - Mo doc not defined in techpub!!!
    choices: [ disabled, enabled ]
    type: str
  match_t:
    description:
    - match criteria
    choices: [ All, AtleastOne, AtmostOne, None ]
    type: str
  name:
    description:
    - Name of Object cloud_external_epg.
    aliases: [ cloud_external_epg ]
    type: str
  name_alias:
    description:
    - Name_alias for object cloud_external_epg.
    type: str
  preferred_group_member:
    description:
    - Represents parameter used to determine if EPg is part of a group that does not a contract for communication.
    choices: [ exclude, include ]
    type: str
  prio:
    description:
    - qos priority class id
    choices: [ level1, level2, level3, level4, level5, level6, unspecified ]
    type: str
  route_reachability:
    description:
    - Route reachability for this EPG.
    choices: [ inter-site, internet, unspecified ]
    type: str
  tenant:
    description:
    - Tenant name
    type: str
  ap:
    description:
    - Parent object name
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    choices: [ absent, present, query ]
    default: present
    type: str
extends_documentation_fragment:
- cisco.aci.aci

notes:
- More information about the internal APIC class B(cloud:BgpAsP) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
'''

EXAMPLES = r'''
- name: Add a new cloud BGP ASN
  cisco.aci.aci_cloud_bgp_asn:
    host: apic
    username: admin
    password: SomeSecretPassword
    asn: 64601
    description: ASN description
    name: ASN_1
    state: present
  delegate_to: localhost

- name: Remove a cloud BGP ASN
  cisco.aci.aci_cloud_bgp_asn:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: no
    state: absent
  delegate_to: localhost

- name: Query a cloud BGP ASN
  cisco.aci.aci_cloud_bgp_asn:
    host: apic
    username: admin
    password: SomeSecretPassword
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
                    "name_alias": "",
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
                    "name_alias": "",
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

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update({
        'description': dict(type='str', aliases=['descr']),
        'name': dict(type='str', aliases=['cloud_external_epg']),
        'route_reachability': dict(type='str', choices=['inter-site', 'internet', 'unspecified']),
        'tenant': dict(type='str'),
        'ap': dict(type='str', aliases=['app_profile', 'app_profile_name', 'cloud_application_container']),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),
        'vrf': dict(type='str', aliases=['context', 'vrf_name']),
    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['name', 'tenant', 'ap']],
            ['state', 'present', ['name', 'tenant', 'ap']],
        ],
    )

    description = module.params['description']
    name = module.params['name']
    route_reachability = module.params['route_reachability']
    tenant = module.params['tenant']
    ap = module.params['ap']
    state = module.params['state']
    child_configs=[]
    relation_vrf = module.params['vrf']

    if relation_vrf:
        child_configs.append({'cloudRsCloudEPgCtx': {'attributes': {'tnFvCtxName': relation_vrf}}})

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
            'aci_class': 'cloudExtEPg',
            'aci_rn': 'cloudextepg-{}'.format(name),
            'target_filter': 'eq(cloudExtEPg.name, "{}")'.format(name),
            'module_object': name
        },

        child_classes=['fvRsCustQosPol','cloudRsCloudEPgCtx']

    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudExtEPg',
            class_config={
                'descr': description,
                'name': name,
                'routeReachability': route_reachability,
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
