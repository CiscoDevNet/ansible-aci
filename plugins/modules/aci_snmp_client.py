#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_snmp_client
short_description: Manage SNMP clients (snmp:ClientP).
description:
- Manage SNMP clients
options:
  address:
    description:
    - IP subnet to accept SNMP requests from
    type: str
  client_group:
    description:
    - Name of an existing SNMP client group
    type: str
    aliases: [ client_group_name, client_group_profile ]
  client_name:
    description:
    - Name of the SNMP client
    type: str
  policy:
    description:
    - Name of an existing SNMP policy
    type: str
    aliases: [ snmp_policy, snmp_policy_name ]
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(snmp:ClientP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Create an SNMP client
  cisco.aci.aci_snmp_client:
    host: apic
    username: admin
    password: SomeSecretPassword
    policy: my_snmp_policy
    client_group: my_snmp_client_group
    address: 10.20.30.0/24
    client_name: my_client_name
    state: present
  delegate_to: localhost

- name: Remove an SNMP client
  cisco.aci.aci_snmp_client_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    policy: my_snmp_policy
    client_group: my_snmp_client_group
    address: 10.20.30.0/24
    state: absent
  delegate_to: localhost

- name: Query an SNMP client
  cisco.aci.aci_snmp_client:
    host: apic
    username: admin
    password: SomeSecretPassword
    policy: my_snmp_policy
    client_group: my_snmp_client_group
    address: 10.20.30.0/24
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all SNMP clients
  cisco.aci.aci_snmp_client:
    host: apic
    username: admin
    password: SomeSecretPassword
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


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        address=dict(type="str"),
        client_group=dict(type="str", aliases=["client_group_name", "client_group_profile"]),
        policy=dict(type="str", aliases=["snmp_policy", "snmp_policy_name"]),
        client_name=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["policy", "client_group", "address"]],
            ["state", "present", ["policy", "client_group", "address"]],
        ],
    )

    aci = ACIModule(module)

    client_group = module.params.get("client_group")
    policy = module.params.get("policy")
    client_name = module.params.get("client_name")
    address = module.params.get("address")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="snmpPol",
            aci_rn="fabric/snmppol-{0}".format(policy),
            module_object=policy,
            target_filter={"name": policy},
        ),
        subclass_1=dict(
            aci_class="snmpClientGrpP",
            aci_rn="clgrp-{0}".format(client_group),
            module_object=client_group,
            target_filter={"name": client_group},
        ),
        subclass_2=dict(
            aci_class="snmpClientP",
            aci_rn="client-[{0}]".format(address),
            module_object=address,
            target_filter={"addr": address},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="snmpClientP",
            class_config=dict(addr=address, name=client_name),
        )

        aci.get_diff(aci_class="snmpClientP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
