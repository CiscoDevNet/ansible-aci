#!/usr/bin/python


# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = """
---
module: aci_firmware_policy

short_description: This creates a firmware policy


description:
    - This module creates a firmware policy for firmware groups. The firmware policy is create first and then
    - referenced by the firmware group. You will assign the firmware and specify if you want to ignore the compatibility
    - check
options:
    name:
        description:
            - Name of the firmware policy
        type: str
    version:
        description:
            - The version of the firmware associated with this policy. This value is very import as well as constructing
            - it correctly. The syntax for this field is n9000-xx.x. If you look at the firmware repository using the UI
            - each version will have a "Full Version" column, this is the value you need to use. So, if the Full Version
            - is 13.1(1i), the value for this field would be n9000-13.1(1i)
        type: str
    ignoreCompat:
        description:
            - Check if compatibility checks should be ignored
        type: bool
    state:
        description:
            - Use C(present) or C(absent) for adding or removing.
            - Use C(query) for listing an object or multiple objects.
        type: str
        choices: [absent, present, query]
        default: present
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
   - name: firmware policy
     cisco.aci.aci_firmware_policy:
        host: "{{ inventory_hostname }}"
        username: "{{ user }}"
        password: "{{ pass }}"
        validate_certs: false
        name: test2FrmPol
        version: n9000-13.2(1m)
        ignoreCompat: False
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
        name=dict(type="str"),  # Not required for querying all objects
        version=dict(type="str"),
        ignoreCompat=dict(type="bool"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name", "version"]],
        ],
    )

    state = module.params.get("state")
    name = module.params.get("name")
    version = module.params.get("version")
    name_alias = module.params.get("name_alias")

    if module.params.get("ignoreCompat"):
        ignore = "yes"
    else:
        ignore = "no"

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="firmwareFwP",
            aci_rn="fabric/fwpol-{0}".format(name),
            target_filter={"name": name},
            module_object=name,
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="firmwareFwP",
            class_config=dict(
                name=name,
                version=version,
                ignoreCompat=ignore,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="firmwareFwP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
