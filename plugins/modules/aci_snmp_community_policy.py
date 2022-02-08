#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_snmp_community_policy
short_description: Manage SNMP community policies (snmp:CommunityP).
description:
- Manage SNMP community policies
options:
  community:
    description:
    - Name of the SNMP community policy
    type: str
  description:
    description:
    - Description of the SNMP policy
    type: str
  policy:
    description:
    - Name of an existing SNMP policy
    type: str
    aliases: [ snmp_policy, snmp_policy_name ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  annotation:
    description:
      - The default value for the annotation attribute is 'orchestrator:Ansible'.
    type: str
    default: orchestrator:Ansible
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(snmp:CommunityP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Create an SNMP community policy
  cisco.aci.aci_snmp_community_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    policy: my_snmp_policy
    community: my_snmp_community
    state: present
  delegate_to: localhost

- name: Remove an SNMP community policy
  cisco.aci.aci_snmp_community_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    policy: my_snmp_policy
    community: my_snmp_community
    state: absent
  delegate_to: localhost

- name: Query an SNMP community policy
  cisco.aci.aci_snmp_community_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    policy: my_snmp_policy
    community: my_snmp_community
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all SNMP community policies
  cisco.aci.aci_snmp_community_policy:
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


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        community=dict(type="str"),
        policy=dict(type="str", aliases=["snmp_policy", "snmp_policy_name"]),
        description=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["policy", "community"]],
            ["state", "present", ["policy", "community"]],
        ],
    )

    aci = ACIModule(module)

    community = module.params.get("community")
    policy = module.params.get("policy")
    description = module.params.get("description")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="snmpPol",
            aci_rn="fabric/snmppol-{0}".format(policy),
            module_object=policy,
            target_filter={"name": policy},
        ),
        subclass_1=dict(
            aci_class="snmpCommunityP",
            aci_rn="community-{0}".format(community),
            module_object=community,
            target_filter={"name": community},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="snmpCommunityP",
            class_config=dict(name=community, descr=description),
        )

        aci.get_diff(aci_class="snmpCommunityP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
