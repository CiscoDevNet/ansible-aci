#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Tim Cragg (@timcragg) <tcragg@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_route_control_match_dest
short_description: Manage Route Control Match Destination Rule objects (rtctrl:MatchRtDest)
description:
- Manage Route Control Match Destination Rules on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  subject_name:
    description:
    - Name of the Match Rule object.
    type: str
  ip:
    description:
    - Match Prefix IP in the CIDR format.
    type: str
  aggregate:
    description:
    - When Aggregate is false, the IP addresses are matched exactly.
    type: bool
  greater_than_mask:
    description:
    - Prefix length to match, in the range of 0 to 128 and greater_than_mask must be larger than Mask Length.
    type: int
    aliases: [ less_than, lt ]
  less_than_mask:
    description:
    - Prefix length to match, in the range of 0 to 128 and greater_than_mask cannot be larger than less_than_mask.
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
- cisco.aci.annotation

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

- name: Query All Route Control Match Destinations
  cisco.aci.aci_route_control_match_dest:
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

import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
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

    ipv4_regex = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[0-2][0-9]|3[0-2])$"
    ipv6_regex = r"^(?:(?:(?:[A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})|::[A-Fa-f0-9]{1,4})/(?:[0-9]|[0-9][0-9]|1[01][0-9]|12[0-8])$"
    combined_regex = r"(?:{0}|{1})".format(ipv4_regex, ipv6_regex)

    if ip is not None:
        if "/" not in ip:
            aci.fail_json("ip must include the prefix length, e.g. '10.20.30.0/24' or 'fd80::/64'")
        elif not re.search(combined_regex, ip):
            aci.fail_json("ip must be a valid IPv4 or IPv6 prefix, e.g. '10.20.30.0/24' or 'fd80::/64'")
        else:
            mask = int(ip.split("/")[1])

    if greater_than is not None:
        if greater_than <= mask and greater_than > 0:
            aci.fail_json(msg="greater_than must be greater than the prefix mask")
        if less_than is not None and less_than > 0 and less_than < greater_than:
            aci.fail_json(msg="greater_than must be less than less_than")

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
            target_filter={"ip": ip},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="rtctrlMatchRtDest",
            class_config=dict(
                ip=ip,
                fromPfxLen=greater_than,
                toPfxLen=less_than,
                aggregate=aggregate,
            ),
        )

        aci.get_diff(aci_class="rtctrlMatchRtDest")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
