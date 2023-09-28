#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_match_community_factor
short_description: Manage Match Community Factor (rtctrl:MatchCommFactor)
description:
- Manage Match Community Factors for Match Rules Based on Community on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  subject_profile:
    description:
    - Name of an exising subject profile.
    type: str
    aliases: [ subject_name ]
  match_community_term:
    description:
    - Name of an existing match community term.
    type: str
    aliases: [ match_rule_name ]
  community:
    description:
    - The match community value.
    type: str
  scope:
    description:
    - The item scope.
    - if the scope is transitive, this community may be passed between ASs.
    - if the scope is Non transitive, this community should be carried only within the local AS.
    type: str
    choices: [ transitive, non-transitive ]
  description:
    description:
    - The description for the Match Community Term.
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
- The C(tenant), the C(subject_profile) and the C(match_community_term) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), the M(cisco.aci.subject_profile) and M(cisco.aci.match_community_term) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(rtctrl:MatchCommFactor).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
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
                    "ownerauto_continue": ""
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
                    "ownerauto_continue": ""
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


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        subject_profile=dict(type="str", aliases=["subject_name"]),  # Not required for querying all objects
        match_community_term=dict(type="str", aliases=["match_rule_name"]),  # Not required for querying all objects
        community=dict(type="str"),
        scope=dict(type="str", choices=["transitive", "non-transitive"]),
        description=dict(type="str", aliases=["descr"]),
        name_alias=dict(type="str"),
        state=dict(type="str", default="present", choices=["present", "absent", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["community", "tenant", "subject_profile", "match_community_term"]],
            ["state", "present", ["community", "tenant", "subject_profile", "match_community_term"]],
        ],
    )

    community = module.params.get("community")
    scope = module.params.get("scope")
    description = module.params.get("description")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    subject_profile = module.params.get("subject_profile")
    match_community_term = module.params.get("match_community_term")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="rtctrlSubjP",
            aci_rn="subj-{0}".format(subject_profile),
            module_object=subject_profile,
            target_filter={"name": subject_profile},
        ),
        subclass_2=dict(
            aci_class="rtctrlMatchCommTerm",
            aci_rn="commtrm-{0}".format(match_community_term),
            module_object=match_community_term,
            target_filter={"name": match_community_term},
        ),
        subclass_3=dict(
            aci_class="rtctrlMatchCommFactor",
            aci_rn="commfct-{0}".format(community),
            module_object=community,
            target_filter={"community": community},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="rtctrlMatchCommFactor",
            class_config=dict(
                community=community,
                scope=scope,
                descr=description,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="rtctrlMatchCommFactor")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
