#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_route_control_match_dest
short_description: Manage Route Control Match Destination objects (rtctrlMatchRtDest)
description:
- Manage Route Control Match Destination on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  subject_name:
    description:
    - Subject name
    type: str
  ip:
    description:
    - IP prefix in CIDR format
    type: str
  aggregate:
    description:
    - When Aggregate is false, the IP addresses are matched exactly
    type: boolean
  greater_than_mask:
    description:
    - prefix length to match. 0 is considered unspecified
    type: int
    aliases: [ less_than, lt ]
  less_than_mask:
    description:
    - prefix length to match. 0 is considered unspecified
    type: int
    aliases: [ greater_than, gt ]
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
- The C(tenant) and C(subject_name) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_route_control_subject) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_route_control_subject
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(rtctrl:MatchRtDest).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new Route Control Match Destination
  cisco.aci.aci_route_control_match_dest:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    subject_name: my_subject
    ip: 10.20.30.0/24
    aggregate: no
    greater_than_mask: 26
    less_than_mask: 28
    state: present
  delegate_to: localhost

- name: Delete Route Control Match Destination
  cisco.aci.aci_route_control_match_dest:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    subject_name: my_subject
    ip: 10.20.30.0/24
    state: absent
  delegate_to: localhost

- name: Query Route Control Match Destination
  cisco.aci.aci_route_control_match_dest:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    subject_name: my_subject
    ip: 10.20.30.0/24
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        subject_name=dict(type="str"),
        ip=dict(type="str"),
        aggregate=dict(type="bool"),
        greater_than_mask=dict(type="int", aliases=["greater_than", "gt"]),
        less_than_mask=dict(type="int", aliases=["less_than", "lt"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "subject_name", "ip"]],
            ["state", "present", ["tenant", "subject_name", "ip"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    subject_name = module.params.get("subject_name")
    ip = module.params.get("ip")
    aggregate = aci.boolean(module.params.get("aggregate"))
    greater_than = module.params.get("greater_than_mask")
    less_than = module.params.get("less_than_mask")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="rtctrlSubj",
            aci_rn="subj-{0}".format(subject_name),
            module_object=subject_name,
            target_filter={"name": subject_name},
        ),
        subclass_2=dict(
            aci_class="rtctrlMatchRtDest",
            aci_rn="dest-[{0}]".format(ip),
            module_object=ip,
            target_filter={"name": ip},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="rtctrlMatchRtDest",
            class_config=dict(
                name=profile,
                descr=description,
                type=prof_type,
                dn="uni/tn-{0}/subj-{1}/dest-[{2}]".format(tenant, subject, ip),
            ),
        )

        aci.get_diff(aci_class="rtctrlMatchRtDest")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
