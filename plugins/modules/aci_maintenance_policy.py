#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_maintenance_policy
short_description: Manage firmware maintenance policies
description:
- Manage maintenance policies that defines behavior during an ACI upgrade.
options:
  name:
    description:
    - The name for the maintenance policy.
    type: str
    aliases: [ maintenance_policy ]
  runmode:
    description:
    - Whether the system pauses on error or just continues through it.
    type: str
    choices: [ pauseOnlyOnFailures, pauseNever ]
    default: pauseOnlyOnFailures
  graceful:
    description:
    - Whether the system will bring down the nodes gracefully during an upgrade, which reduces traffic lost.
    - The APIC defaults to C(no) when unset during creation.
    type: bool
  scheduler:
    description:
    - The name of scheduler that is applied to the policy.
    type: str
  adminst:
    description:
    - Will trigger an immediate upgrade for nodes if adminst is set to triggered.
    type: str
    choices: [ triggered, untriggered ]
    default: untriggered
  ignoreCompat:
    description:
    - To check whether compatibility checks should be ignored
    - The APIC defaults to C(no) when unset during creation.
    type: bool
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

notes:
- A scheduler is required for this module, which could have been created using the M(cisco.aci.aci_fabric_scheduler) module or via the UI.
author:
- Steven Gerhart (@sgerhart)
"""

EXAMPLES = r"""
- name: Create a maintenance policy
  cisco.aci.aci_maintenance_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_maintenance_policy
    scheduler: simpleScheduler
    state: present
  delegate_to: localhost

- name: Delete a maintenance policy
  cisco.aci.aci_maintenance_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_maintenance_policy
    state: absent
  delegate_to: localhost

- name: Query all maintenance policies
  cisco.aci.aci_maintenance_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific maintenance policy
  cisco.aci.aci_maintenance_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_maintenance_policy
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
        name=dict(type="str", aliases=["maintenance_policy"]),  # Not required for querying all objects
        runmode=dict(type="str", default="pauseOnlyOnFailures", choices=["pauseOnlyOnFailures", "pauseNever"]),
        graceful=dict(type="bool"),
        scheduler=dict(type="str"),
        ignoreCompat=dict(type="bool"),
        adminst=dict(type="str", default="untriggered", choices=["triggered", "untriggered"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name", "scheduler"]],
        ],
    )

    aci = ACIModule(module)

    state = module.params.get("state")
    name = module.params.get("name")
    runmode = module.params.get("runmode")
    scheduler = module.params.get("scheduler")
    adminst = module.params.get("adminst")
    graceful = aci.boolean(module.params.get("graceful"))
    ignoreCompat = aci.boolean(module.params.get("ignoreCompat"))
    name_alias = module.params.get("name_alias")

    aci.construct_url(
        root_class=dict(
            aci_class="maintMaintP",
            aci_rn="fabric/maintpol-{0}".format(name),
            target_filter={"name": name},
            module_object=name,
        ),
        child_classes=["maintRsPolScheduler"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="maintMaintP",
            class_config=dict(
                name=name,
                runMode=runmode,
                graceful=graceful,
                adminSt=adminst,
                ignoreCompat=ignoreCompat,
                nameAlias=name_alias,
            ),
            child_configs=[
                dict(
                    maintRsPolScheduler=dict(
                        attributes=dict(
                            tnTrigSchedPName=scheduler,
                        ),
                    ),
                ),
            ],
        )

        aci.get_diff(aci_class="maintMaintP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
