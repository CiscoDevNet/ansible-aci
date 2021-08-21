#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, nkatarmal-crest <nirav.katarmal@crestdatasys.com>
# Copyright: (c) 2021, Shreyas Srish <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: aci_cloud_aws_provider
short_description: Manage Cloud AWS Provider (cloud:AwsProvider)
description:
- Manage AWS provider on Cisco Cloud ACI.
author:
- Devarshi Shah (@devarshishah3)
options:
  access_key_id:
    description:
    - Cloud Access Key ID.
    type: str
  account_id:
    description:
    - AWS Account ID.
    type: str
  email:
    description:
    - Account Email Address.
    type: str
  http_proxy:
    description:
    - Http Proxy to connect to cloud provider.
    type: str
  is_account_in_org:
    description:
    - Is Account in Organization.
    type: bool
  is_trusted:
    description:
    - Trusted Tenant
    type: bool
  provider_id:
    description:
    - AWS provider id
    type: str
  region:
    description:
    - AWS Region.
    type: str
  secret_access_key:
    description:
    - Cloud Secret Access Key.
    type: str
  tenant:
    description:
    - Name of tenant.
    type: str
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
  - More information about the internal APIC class B(cloud:AwsProvider) from
  - L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
'''

EXAMPLES = r'''
- name: Create aws provider again after deletion as not trusted
  cisco.aci.aci_cloud_aws_provider:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_test
    account_id: 111111111111
    is_trusted: yes
    state: present
  delegate_to: localhost

- name: Delete aws provider
  cisco.aci.aci_cloud_aws_provider:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_test
    account_id: 111111111111
    is_trusted: yes
    state: absent
  delegate_to: localhost

- name: Query aws provider
  cisco.aci.aci_cloud_aws_provider:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_test
    state: query
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

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update({
        'access_key_id': dict(type='str'),
        'account_id': dict(type='str'),
        'email': dict(type='str'),
        'http_proxy': dict(type='str'),
        'is_account_in_org': dict(type='bool'),
        'is_trusted': dict(type='bool'),
        'provider_id': dict(type='str'),
        'region': dict(type='str'),
        'secret_access_key': dict(type='str'),
        'tenant': dict(type='str'),
        'state': dict(type='str', default='present', choices=['absent', 'present', 'query']),

    })

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['tenant']],
            ['state', 'present', ['tenant']],
        ],
    )

    aci = ACIModule(module)

    access_key_id = module.params.get('access_key_id')
    account_id = module.params.get('account_id')
    annotation = module.params.get('annotation')
    email = module.params.get('email')
    http_proxy = module.params.get('http_proxy')
    is_account_in_org = aci.boolean(module.params.get('is_account_in_org'))
    is_trusted = aci.boolean(module.params.get('is_trusted'))
    provider_id = module.params.get('provider_id')
    region = module.params.get('region')
    secret_access_key = module.params.get('secret_access_key')
    tenant = module.params.get('tenant')
    state = module.params.get('state')
    child_configs = []

    aci.construct_url(
        root_class={
            'aci_class': 'fvTenant',
            'aci_rn': 'tn-{0}'.format(tenant),
            'target_filter': 'eq(fvTenant.name, "{0}")'.format(tenant),
            'module_object': tenant
        },
        subclass_1={
            'aci_class': 'cloudAwsProvider',
            'aci_rn': 'awsprovider'.format(),
            'target_filter': '',
            'module_object': None
        },

        child_classes=[]

    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='cloudAwsProvider',
            class_config={
                'accessKeyId': access_key_id,
                'accountId': account_id,
                'annotation': annotation,
                'email': email,
                'httpProxy': http_proxy,
                'isAccountInOrg': is_account_in_org,
                'isTrusted': is_trusted,
                'providerId': provider_id,
                'region': region,
                'secretAccessKey': secret_access_key,
            },
            child_configs=child_configs

        )

        aci.get_diff(aci_class='cloudAwsProvider')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
