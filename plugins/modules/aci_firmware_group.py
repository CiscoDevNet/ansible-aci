#!/usr/bin/python

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = """
---
module: aci_firmware_group

short_description: This module creates a firmware group


description:
    - This module creates a firmware group, so that you can apply firmware policy to nodes.
options:
    group:
        description:
            - This the name of the firmware group
        type: str
    firmwarepol:
        description:
            - This is the name of the firmware policy, which was create by aci_firmware_policy. It is important that
            - you use the same name as the policy created with aci_firmware_policy
        type: str
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
- cisco.aci.annotation
- cisco.aci.owner

author:
    - Steven Gerhart (@sgerhart)
"""

# FIXME: Add more, better examples
EXAMPLES = r"""
    - name: firmware group
      cisco.aci.aci_firmware_group:
        host: "{{ inventory_hostname }}"
        username: "{{ user }}"
        password: "{{ pass }}"
        validate_certs: no
        group: testingfwgrp1
        firmwarepol: test2FrmPol
        state: present
"""
RETURN = """
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

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        group=dict(type="str"),  # Not required for querying all objects
        firmwarepol=dict(type="str"),  # Not required for querying all objects
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["group"]],
            ["state", "present", ["group", "firmwarepol"]],
        ],
    )

    state = module.params.get("state")
    group = module.params.get("group")
    firmwarepol = module.params.get("firmwarepol")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="firmwareFwGrp",
            aci_rn="fabric/fwgrp-{0}".format(group),
            target_filter={"name": group},
            module_object=group,
        ),
        child_classes=["firmwareRsFwgrpp"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="firmwareFwGrp",
            class_config=dict(
                name=group,
                nameAlias=name_alias,
            ),
            child_configs=[
                dict(
                    firmwareRsFwgrpp=dict(
                        attributes=dict(
                            tnFirmwareFwPName=firmwarepol,
                        ),
                    ),
                ),
            ],
        )

        aci.get_diff(aci_class="firmwareFwGrp")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
