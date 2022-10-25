#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Sudhakar Shet Kudtarkar (@kudtarkar1)
# Copyright: (c) 2020, Shreyas Srish <ssrish@cisco.com>
# Copyright: (c) 2022, Mark Ciecior (@markciecior)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l3out_extepg_to_subject_label
short_description: Bind Subject Labels to External End Point Groups (EPGs)
description:
- Bind Subject Labels to External End Point Groups (EPGs) on ACI fabrics.
options:
  tenant:
    description:
    - Name of existing tenant.
    type: str
  l3out:
    description:
    - Name of the l3out.
    type: str
    aliases: ['l3out_name']
  extepg:
    description:
    - Name of the external end point group.
    type: str
    aliases: ['extepg_name', 'external_epg']
  subject_label:
    description:
    - Name of the subject label.
    type: str
  contract_type:
    description:
    - The type of contract.
    type: str
    required: yes
    choices: ['consumer', 'provider']
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
- The C(tenant), C(l3out) and C(extepg) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l3out) and M(cisco.aci.aci_l3out_extepg) modules can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fvtenant), B(l3extInstP) and B(l3extOut).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sudhakar Shet Kudtarkar (@kudtarkar1)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Bind a subject label to an external EPG
  cisco.aci.aci_l3out_extepg_to_subject_label:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: Auto-Demo
    l3out: l3out
    extepg : testEpg
    subject_label: my_test_label
    contract_type: provider
    state: present
  delegate_to: localhost

- name: Remove existing subject label from an external EPG
  cisco.aci.aci_l3out_extepg_to_subject_label:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: Auto-Demo
    l3out: l3out
    extepg : testEpg
    subject_label: my_test_label
    contract_type: provider
    state: absent
  delegate_to: localhost

- name: Query a subject label bound to an external EPG
  cisco.aci.aci_l3out_extepg_to_subject_label:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    l3out: ansible_l3out
    extepg: ansible_extEpg
    subject_label: my_test_label
    contract_type: provider
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all contracts relationships
  cisco.aci.aci_l3out_extepg_to_subject_label:
    host: apic
    username: admin
    password: SomeSecretePassword
    contract_type: provider
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
     sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class "/></imdata>'
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

ACI_CLASS_MAPPING = dict(
    consumer={
        "class": "vzConsSubjLbl",
        "rn": "conssubjlbl-",
    },
    provider={
        "class": "vzProvSubjLbl",
        "rn": "provsubjlbl-",
    },
)

def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        contract_type=dict(type="str", required=True, choices=["consumer", "provider"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        subject_label=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        tenant=dict(type="str"),
        extepg=dict(type="str", aliases=["extepg_name", "external_epg"]),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["extepg", "subject_label", "l3out", "tenant"]],
            ["state", "present", ["extepg", "subject_label", "l3out", "tenant"]],
        ],
    )

    l3out = module.params.get("l3out")
    subject_label = module.params.get("subject_label")
    contract_type = module.params.get("contract_type")
    extepg = module.params.get("extepg")
    state = module.params.get("state")
    tenant = module.params.get("tenant")

    aci_class = ACI_CLASS_MAPPING.get(contract_type)["class"]
    aci_rn = ACI_CLASS_MAPPING.get(contract_type)["rn"]

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="l3extOut",
            aci_rn="out-{0}".format(l3out),
            module_object=l3out,
            target_filter={"name": l3out},
        ),
        subclass_2=dict(
            aci_class="l3extInstP",
            aci_rn="instP-{0}".format(extepg),
            module_object=extepg,
            target_filter={"name": extepg},
        ),
        subclass_3=dict(
            aci_class=aci_class,
            aci_rn="{0}{1}".format(aci_rn, subject_label),
            module_object=subject_label,
            target_filter={"name": subject_label},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=aci_class,
            class_config=dict(
                name=subject_label,
            ),
        )

        aci.get_diff(aci_class=aci_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
