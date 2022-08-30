#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_contract_subject_to_label
short_description: Add labels to contract subjects (vz:ConsSubjLbl) and (vz:ProvSubjLbl)
description:
- Add labels to contracts on Cisco ACI fabrics.
options:
  contract:
    description:
    - The name of the contract.
    type: str
    aliases: [ contract_name ]
  label:
    description:
    - The name of the label to bind to the Subject.
    type: str
    aliases: [ label_name ]
  direction:
    description:
    - Determines if this is a consumer or provider label
    type: str
    choices: [ consumer, provider ]
  subject:
    description:
    - The name of the Contract Subject.
    type: str
    aliases: [ contract_subject, subject_name ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  tenant:
    description:
    - The name of the tenant.
    type: str
    aliases: [ tenant_name ]
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- The C(tenant), C(contract), and C(subject) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_contract), and M(cisco.aci.aci_contract_subject) modules can be used for these.
seealso:
- module: cisco.aci.aci_contract_subject
- module: cisco.aci.aci_filter
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(vz:ConsSubjLbl) B(vz:ProvSubjLbl).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Jacob McGill (@jmcgill298)
"""

EXAMPLES = r"""
- name: Add a new contract subject to label binding
  cisco.aci.aci_contract_subject_to_label:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web_to_db
    subject: test
    label: '{{ label_name }}'
    direction: '{{ direction }}'
    state: present
  delegate_to: localhost

- name: Remove an existing contract subject to label binding
  cisco.aci.aci_contract_subject_to_label:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web_to_db
    subject: test
    label: '{{ label }}'
    direction: '{{ direction }}'
    state: present
  delegate_to: localhost

- name: Query a specific contract subject to label binding
  cisco.aci.aci_contract_subject_to_label:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web_to_db
    subject: test
    label: '{{ label }}'
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all contract subject to label bindings
  cisco.aci.aci_contract_subject_to_label:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web_to_db
    subject: test
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
        contract=dict(type="str", aliases=["contract_name"]),  # Not required for querying all objects
        label=dict(type="str", aliases=["label_name"]),  # Not required for querying all objects
        subject=dict(type="str", aliases=["contract_subject", "subject_name"]),  # Not required for querying all objects
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        direction=dict(type="str", choices=["consumer", "provider"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["contract", "label", "subject", "tenant", "direction"]],
            ["state", "present", ["contract", "label", "subject", "tenant", "direction"]],
        ],
    )

    contract = module.params.get("contract")
    label_name = module.params.get("label")
    subject = module.params.get("subject")
    tenant = module.params.get("tenant")
    direction = module.params.get("direction")
    state = module.params.get("state")

    aci = ACIModule(module)

    if direction == "consumer":
        aci.construct_url(
            root_class=dict(
                aci_class="fvTenant",
                aci_rn="tn-{0}".format(tenant),
                module_object=tenant,
                target_filter={"name": tenant},
            ),
            subclass_1=dict(
                aci_class="vzBrCP",
                aci_rn="brc-{0}".format(contract),
                module_object=contract,
                target_filter={"name": contract},
            ),
            subclass_2=dict(
                aci_class="vzSubj",
                aci_rn="subj-{0}".format(subject),
                module_object=subject,
                target_filter={"name": subject},
            ),
            subclass_3=dict(
                aci_class="vzConsSubjLbl",
                aci_rn="conssubjlbl-{0}".format(label_name),
                module_object=label_name,
                target_filter={"name": label_name},
            ),
        )
    elif direction == "provider":
        aci.construct_url(
            root_class=dict(
                aci_class="fvTenant",
                aci_rn="tn-{0}".format(tenant),
                module_object=tenant,
                target_filter={"name": tenant},
            ),
            subclass_1=dict(
                aci_class="vzBrCP",
                aci_rn="brc-{0}".format(contract),
                module_object=contract,
                target_filter={"name": contract},
            ),
            subclass_2=dict(
                aci_class="vzSubj",
                aci_rn="subj-{0}".format(subject),
                module_object=subject,
                target_filter={"name": subject},
            ),
            subclass_3=dict(
                aci_class="vzProvSubjLbl",
                aci_rn="provsubjlbl-{0}".format(label_name),
                module_object=label_name,
                target_filter={"name": label_name},
            ),
        )

    aci.get_existing()

    if state == "present":
        if direction == "consumer":
            aci.payload(
                aci_class="vzConsSubjLbl",
                class_config=dict(
                    name=label_name,
                ),
            )

            aci.get_diff(aci_class="vzConsSubjLbl")
            
        elif direction == "provider":
            aci.payload(
                aci_class="vzProvSubjLbl",
                class_config=dict(
                    name=label_name,
                ),
            )

            aci.get_diff(aci_class="vzProvSubjLbl")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
