#!/usr/bin/python

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_maintenance_group_node
short_description: Manage maintenance group nodes
description:
- Manage maintenance group nodes
options:
  group:
    description:
    - The maintenance group name that you want to add the node to.
    type: str
  node:
    description:
    - The node to be added to the maintenance group.
    - The value equals the nodeid.
    type: str
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

author:
- Steven Gerhart (@sgerhart)
"""

EXAMPLES = r"""
- name: maintenance group
  cisco.aci.aci_maintenance_group_node:
    host: "{{ inventory_hostname }}"
    username: "{{ user }}"
    password: "{{ pass }}"
    validate_certs: no
    group: maintenancegrp1
    node: 1001
    state: present

- name: maintenance group
  cisco.aci.aci_maintenance_group_node:
    host: "{{ inventory_hostname }}"
    username: "{{ user }}"
    password: "{{ pass }}"
    validate_certs: no
    group: maintenancegrp1
    node: 1002
    state: absent
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        group=dict(type="str"),  # Not required for querying all objects
        node=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["node", "group"]],
            ["state", "present", ["node", "group"]],
        ],
    )

    state = module.params.get("state")
    group = module.params.get("group")
    node = module.params.get("node")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="maintMaintGrp",
            aci_rn="fabric/maintgrp-{0}".format(group),
            target_filter={"name": group},
            module_object=group,
        ),
        subclass_1=dict(
            aci_class="fabricNodeBlk",
            aci_rn="nodeblk-blk{0}-{0}".format(node),
            target_filter={"name": "blk{0}-{0}".format(node)},
            module_object=node,
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fabricNodeBlk",
            class_config=dict(
                from_=node,
                to_=node,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="fabricNodeBlk")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
