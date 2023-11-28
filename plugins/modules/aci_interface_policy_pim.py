#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Lukas Holub (@lukasholub)
# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_interface_policy_pim
short_description: Manage PIM interface policies (pim:IfPol)
description:
- Manage Protocol Independent Multicast interface policies for Tenants on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing Tenant.
    type: str
    aliases: [ tenant_name ]
  pim:
    description:
    - The PIM interface policy name.
    - Note that you cannot change this name after the object has been created.
    type: str
    aliases: [ pim_interface, name ]
  authentication_key:
    description:
    - The authentication key.
    type: str
  authentication_type:
    description:
    - the authentication type.
    type: str
    choices: [ none, ah_md5 ]
  secure_authentication_key:
    description:
    - The secure authentication key.
    - The APIC defaults to C(cisco) when unset during creation.
    type: str
    aliases: [ secure_key ]
  control_state:
    description:
    - The PIM interface policy control state.
    - 'This is a list of one or more of the following controls:'
    - C(border) -- Boundary of Multicast domain.
    - C(strict_rfc_compliant) -- Only listen to PIM protocol packets.
    - C(passive) -- Do not send/receive PIM protocol packets.
    type: list
    elements: str
    choices: [ border, strict_rfc_compliant, passive ]
  designed_router_delay:
    description:
    - The PIM designed router delay.
    - Accepted values range between C(1) and C(65535).
    - The APIC defaults to C(3) when unset during creation.
    type: int
    aliases: [ delay ]
  designed_router_priority:
    description:
    - The PIM designed router priority.
    - Accepted values range between C(1) and C(4294967295).
    - The APIC defaults to C(1) when unset during creation.
    type: int
    aliases: [ prio ]
  hello_interval:
    description:
    - The time interval in seconds between hello packets that PIM sends on the interface.
    - The smaller the hello interval, the faster topological changes will be detected, but more routing traffic will ensue.
    - Accepted values range between C(1) and C(18724286).
    - The APIC defaults to C(30000) when unset during creation.
    type: int
  join_prune_interval:
    description:
    - The Join Prune interval in seconds.
    - Accepted values range between C(60) and C(65520).
    - The APIC defaults to C(60) when unset during creation.
    type: int
    aliases: [ jp_interval ]
  description:
    description:
    - The description of the PIM interface policy.
    type: str
    aliases: [ descr ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

notes:
- The C(tenant) used must exist before using this module in your playbook.
- The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(pim:IfPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
- Lukas Holub (@lukasholub)
"""

EXAMPLES = r"""
- name: Create an PIM interface policy
  cisco.aci.aci_interface_policy_pim:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    pim: pim1
    control_state: [split-horizon, nh-self]
    designed_router_delay: 10
    designed_router_priority: tens_of_micro
    hello_interval: 5
    join_prune_interval: 15
    state: present
  delegate_to: localhost

- name: Delete PIM interface policy
  cisco.aci.aci_interface_policy_pim:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    pim: pim1
    state: present
  delegate_to: localhost

- name: Query an PIM interface policy
  cisco.aci.aci_interface_policy_pim:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    pim: pim1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all PIM interface policies in tenant production
  cisco.aci.aci_interface_policy_pim:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import (
    MATCH_PIM_INTERFACE_POLICY_CONTROL_STATE_MAPPING,
    MATCH_PIM_INTERFACE_POLICY_AUTHENTICATION_TYPE_MAPPING,
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        pim=dict(type="str", aliases=["pim_interface", "name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        authentication_key=dict(type="str", no_log=True),
        authentication_type=dict(type="str", choices=["none", "ah_md5"]),
        secure_authentication_key=dict(type="str", aliases=["secure_key"], no_log=True),
        control_state=dict(type="list", elements="str", choices=["border", "strict_rfc_compliant", "passive"]),
        designed_router_delay=dict(type="int", aliases=["delay"]),
        designed_router_priority=dict(type="int", aliases=["prio"]),
        hello_interval=dict(type="int"),
        join_prune_interval=dict(type="int", aliases=["jp_interval"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["pim", "tenant"]],
            ["state", "present", ["pim", "tenant"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    pim = module.params.get("pim")
    authentication_key = module.params.get("authentication_key")
    authentication_type = MATCH_PIM_INTERFACE_POLICY_AUTHENTICATION_TYPE_MAPPING.get(module.params.get("authentication_type"))
    secure_authentication_key = module.params.get("secure_authentication_key")
    description = module.params.get("description")
    name_alias = module.params.get("name_alias")
    state = module.params.get("state")

    designed_router_delay = module.params.get("designed_router_delay")
    if designed_router_delay is not None and designed_router_delay not in range(1, 65536):
        module.fail_json(msg="Parameter 'designed_router_delay' is only valid in range between 1 and 65535.")

    designed_router_priority = module.params.get("designed_router_priority")
    if designed_router_priority is not None and designed_router_priority not in range(1, 4294967296):
        module.fail_json(msg="Parameter 'designed_router_priority' is only valid in range between 1 and 4294967295.")

    hello_interval = module.params.get("hello_interval")
    if hello_interval is not None and hello_interval not in range(1, 18724287):
        module.fail_json(msg="Parameter 'hello_interval' is only valid in range between 1 and 18724286.")

    join_prune_interval = module.params.get("join_prune_interval")
    if join_prune_interval is not None and join_prune_interval not in range(60, 65521):
        module.fail_json(msg="Parameter 'join_prune_interval' is only valid in range between 60 and 65520.")

    if module.params.get("control_state"):
        control_state = ",".join([MATCH_PIM_INTERFACE_POLICY_CONTROL_STATE_MAPPING.get(v) for v in module.params.get("control_state")])
    else:
        control_state = None

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="pimIfPol",
            aci_rn="pimifpol-{0}".format(pim),
            module_object=pim,
            target_filter={"name": pim},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="pimIfPol",
            class_config=dict(
                name=pim,
                descr=description,
                authKey=authentication_key,
                authT=authentication_type,
                secureAuthKey=secure_authentication_key,
                ctrl=control_state,
                drDelay=designed_router_delay,
                drPrio=designed_router_priority,
                helloItvl=hello_interval,
                jpInterval=join_prune_interval,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="pimIfPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
