#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Tim Cragg (@timcragg) <tcragg@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_route_control_set_comm
short_description: Manage Route Control Set Community objects (rtctrl:SetComm)
description:
- Manage Route Control Set Community on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  attr_name:
    description:
    - The attribute name.
    type: str
    aliases: [ attribute_name ]
  description:
    description:
    - The description of the Set Community object.
    type: str
    aliases: [ descr ]
  name:
    description:
    - The name of the Set Community object.
    - This defaults to an empty string when creating the Set Community object through the APIC GUI.
    type: str
  community:
    description:
    - The community to set.
    type: str
  set_criteria:
    description:
    - Whether to append or replace communities.
    type: str
    choices: [ append, replace, none ]
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

notes:
- The C(tenant) and C(attr_name) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_route_control_attr) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_route_control_attr
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(rtctrl:SetComm).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new Route Control Community
  cisco.aci.aci_route_control_set_comm:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    attr_name: my_attr
    set_criteria: append
    community: extended:as4-nn2:5:16
    state: present
  delegate_to: localhost

- name: Delete Route Control Community
  cisco.aci.aci_route_control_set_comm:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    attr_name: my_attr
    state: absent
  delegate_to: localhost

- name: Query Route Control Community
  cisco.aci.aci_route_control_set_comm:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    attr_name: my_attr
    state: query
  delegate_to: localhost
  register: query_result

- name: Query All Route Control Communities
  cisco.aci.aci_route_control_set_comm:
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        attr_name=dict(type="str", aliases=["attribute_name"]),
        name=dict(type="str"),
        description=dict(type="str", aliases=["descr"]),
        community=dict(type="str"),
        set_criteria=dict(type="str", choices=["append", "replace", "none"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "attr_name", "community"]],
            ["state", "present", ["tenant", "attr_name", "community"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    attr_name = module.params.get("attr_name")
    description = module.params.get("description")
    community = module.params.get("community")
    name = module.params.get("name")
    set_criteria = module.params.get("set_criteria")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="rtctrlAttrP",
            aci_rn="attr-{0}".format(attr_name),
            module_object=attr_name,
            target_filter={"name": attr_name},
        ),
        subclass_2=dict(
            aci_class="rtctrlSetComm",
            aci_rn="scomm",
            module_object=community,
            target_filter={"community": community},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="rtctrlSetComm",
            class_config=dict(
                name=name,
                descr=description,
                community=community,
                setCriteria=set_criteria,
            ),
        )

        aci.get_diff(aci_class="rtctrlSetComm")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
