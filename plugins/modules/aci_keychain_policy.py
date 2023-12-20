#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_keychain_policy
short_description: Manage KeyChain Policy (fv:KeyChainPol)
description:
- Manage KeyChain Policies for tenants on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  keychain_policy:
    description:
    - The name of the keychain policy.
    type: str
    aliases: [ keychain_policy_name, name ]
  description:
    description:
    - The description for the keychain policy.
    type: str
    aliases: [ descr ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

notes:
- The C(tenant) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Add a new keychain policy
  cisco.aci.aci_keychain_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    keychain_policy: my_keychain_policy
    state: present
  delegate_to: localhost

- name: Delete an keychain policy
  cisco.aci.aci_keychain_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    keychain_policy: my_keychain_policy
    state: absent
  delegate_to: localhost

- name: Query an keychain policy
  cisco.aci.aci_keychain_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    keychain_policy: my_keychain_policy
    state: query
  delegate_to: localhost
  register: query_result

- name: Query an keychain policy in my_tenant
  cisco.aci.aci_keychain_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    state: query
  delegate_to: localhost
  register: query_result
"""

RETURN = r"""
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
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        keychain_policy=dict(type="str", aliases=["keychain_policy_name", "name"], no_log=False),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "keychain_policy"]],
            ["state", "present", ["tenant", "keychain_policy"]],
        ],
    )

    tenant = module.params.get("tenant")
    description = module.params.get("description")
    keychain_policy = module.params.get("keychain_policy")
    state = module.params.get("state")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="fvKeyChainPol",
            aci_rn="keychainp-{0}".format(keychain_policy),
            module_object=keychain_policy,
            target_filter={"name": keychain_policy},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fvKeyChainPol",
            class_config=dict(
                name=keychain_policy,
                descr=description,
            ),
        )

        aci.get_diff(aci_class="fvKeyChainPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
