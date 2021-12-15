#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_vrf
short_description: Manage contexts or VRFs (fv:Ctx)
description:
- Manage contexts or VRFs on Cisco ACI fabrics.
- Each context is a private network associated to a tenant, i.e. VRF.
- Enable Preferred Groups for VRF
options:
  tenant:
    description:
    - The name of the Tenant the VRF should belong to.
    type: str
    aliases: [ tenant_name ]
  vrf:
    description:
    - The name of the VRF.
    type: str
    aliases: [ context, name, vrf_name ]
  policy_control_direction:
    description:
    - Determines if the policy should be enforced by the fabric on ingress or egress.
    type: str
    choices: [ egress, ingress ]
  policy_control_preference:
    description:
    - Determines if the fabric should enforce contract policies to allow routing and packet forwarding.
    type: str
    choices: [ enforced, unenforced ]
  description:
    description:
    - The description for the VRF.
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
  preferred_group:
    description:
    - Enables preferred groups for the VRF under vzAny
    type: str
    choices: [enabled, disabled]
  match_type:
    description:
    - Configures match type for contracts under vzAny
    type: str
    choices: [ all, at_least_one, at_most_one, none]
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

notes:
- The C(tenant) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:Ctx).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Jacob McGill (@jmcgill298)
"""

EXAMPLES = r"""
- name: Add a new VRF to a tenant
  cisco.aci.aci_vrf:
    host: apic
    username: admin
    password: SomeSecretPassword
    vrf: vrf_lab
    tenant: lab_tenant
    descr: Lab VRF
    policy_control_preference: enforced
    policy_control_direction: ingress
    state: present
  delegate_to: localhost

- name: Remove a VRF for a tenant
  cisco.aci.aci_vrf:
    host: apic
    username: admin
    password: SomeSecretPassword
    vrf: vrf_lab
    tenant: lab_tenant
    state: absent
  delegate_to: localhost

- name: Query a VRF of a tenant
  cisco.aci.aci_vrf:
    host: apic
    username: admin
    password: SomeSecretPassword
    vrf: vrf_lab
    tenant: lab_tenant
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all VRFs
  cisco.aci.aci_vrf:
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec

MATCH_TYPE_MAPPING = dict(
    all="All",
    at_least_one="AtleastOne",
    at_most_one="AtmostOne",
    none="None",
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        vrf=dict(type="str", aliases=["context", "name", "vrf_name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        policy_control_direction=dict(type="str", choices=["egress", "ingress"]),
        policy_control_preference=dict(type="str", choices=["enforced", "unenforced"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        preferred_group=dict(type="str", choices=["enabled", "disabled"]),
        match_type=dict(type="str", choices=["all", "at_least_one", "at_most_one", "none"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "vrf"]],
            ["state", "present", ["tenant", "vrf"]],
        ],
    )

    description = module.params.get("description")
    policy_control_direction = module.params.get("policy_control_direction")
    policy_control_preference = module.params.get("policy_control_preference")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    vrf = module.params.get("vrf")
    name_alias = module.params.get("name_alias")
    preferred_group = module.params.get("preferred_group")
    match_type = module.params.get("match_type")

    if match_type is not None:
        match_type = MATCH_TYPE_MAPPING[match_type]

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="fvCtx",
            aci_rn="ctx-{0}".format(vrf),
            module_object=vrf,
            target_filter={"name": vrf},
        ),
        child_classes=["vzAny"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fvCtx",
            class_config=dict(
                descr=description,
                pcEnfDir=policy_control_direction,
                pcEnfPref=policy_control_preference,
                name=vrf,
                nameAlias=name_alias,
            ),
            child_configs=[
                dict(vzAny=dict(attributes=dict(prefGrMemb=preferred_group, matchT=match_type))),
            ],
        )

        aci.get_diff(aci_class="fvCtx")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
