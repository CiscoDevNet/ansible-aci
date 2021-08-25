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
module: aci_l4l7_policy_based_redirect_dest_health_group
short_description: Manage L4-L7 Policy Based Redirect Health Groups (vns:RsRedirectHealthGroup)
description:
- Bind a Health Group to an existing L4-L7 Policy Based Redirect Destination
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
    required: yes
  policy:
    description:
    - Name of an existing Policy Based Redirect Policy
    type: str
    aliases: [ policy_name ]
    required: yes
  redirect_ip:
    description:
    - Destination IP for redirection
    type: str
    required: yes
  health_group:
    description:
    - Name of an existing Health Group
    type: str
    required: yes
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci

notes:
- The C(tenant), C(policy), C(redirect_ip) and C(health_group) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l4l7_policy_based_redirect),
  M(cisco.aci.aci_l4l7_policy_based_redirect_dest) and M(cisco.aci.aci_l4l7_redirect_health_group) modules can be used for this.
seealso:
- module: aci_l3out
- module: aci_l3out_logical_node_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC class vnsRsRedirectHealthGroup
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg
'''

EXAMPLES = r'''
- name: Bind a Health Group to a Policy Based Redirect Destination
  cisco.aci.aci_l4l7_policy_based_redirect_dest_health_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy: my_pbr_policy
    redirect_ip: 192.168.10.1
    health_group: my_health_group
    state: present
  delegate_to: localhost

- name: Remove the Health Group from a Policy Based Redirect Destination
  cisco.aci.aci_l4l7_policy_based_redirect_dest_health_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy: my_pbr_policy
    redirect_ip: 192.168.10.1
    health_group: my_health_group
    state: absent
  delegate_to: localhost

- name: Query the Health Group for a Policy Based Redirect Destination
  cisco.aci.aci_l4l7_policy_based_redirect_dest_health_group
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy: my_pbr_policy
    redirect_ip: 192.168.10.1
    health_group: my_health_group
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
        policy=dict(type='str', aliases=['policy_name'], required=True),
        redirect_ip=dict(type='str', required=True),
        state=dict(type='str', default='present',
                   choices=['absent', 'present', 'query']),
        health_group=dict(type='str', required=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    tenant = module.params.get('tenant')
    policy = module.params.get('policy')
    redirect_ip = module.params.get('redirect_ip')
    state = module.params.get('state')
    health_group = module.params.get('health_group')

    tdn = 'uni/tn-{0}/svcCont/redirectHealthGroup-{1}'.format(tenant,
                                                              health_group)

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant},
        ),
        subclass_1=dict(
            aci_class='vnsSvcRedirectPol',
            aci_rn='svcCont/svcRedirectPol-{0}'.format(policy),
            module_object=policy,
            target_filter={'name': policy},
        ),
        subclass_2=dict(
            aci_class='vnsRedirectDest',
            aci_rn='RedirectDest_ip-[{0}]'.format(redirect_ip),
            module_object=redirect_ip,
            target_filter={'ip': redirect_ip},
        ),
        subclass_3=dict(
            aci_class='vnsRsRedirectHealthGroup',
            aci_rn='rsRedirectHealthGroup',
            module_object=tdn,
            target_filter={'tDn': tdn},
        )
    )
    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='vnsRsRedirectHealthGroup',
            class_config=dict(
                tDn=tdn
            ),
        )
        aci.get_diff(aci_class='vnsRsRedirectHealthGroup')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
