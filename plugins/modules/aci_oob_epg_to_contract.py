#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Eduardo Pozo <ep@devkom.no>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: aci_oob_epg_to_contract
short_description: Manage out-of-band contract association with an out-of-band management EPG.
description:
- This module manages the contract association (mgmtRsOoBProv) under an out-of-band management EPG (mgmtOoB) within the Cisco ACI mgmt tenant.
options:
  epg:
    description:
    - The name of the out-of-band management EPG (under mgmtp-default) where the contract will be associated.
    type: str
    required: true
  contract:
    description:
    - The name of the out-of-band contract to be provided by the management EPG.
    type: str
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(mgmt:OoB) and B(mgmt:InB).
  link: https://developer.cisco.com/docs/apic-mim-ref/

author:
- Eduardo Pozo (@edudppaz)
"""

EXAMPLES = r"""
- name: Associate contract to an out-of-band EPG
  cisco.aci.aci_oob_epg_to_contract:
    epg: default
    contract: default
    state: present
  delegate_to: localhost

- name: Query all contracts associated with an out-of-band EPG
  cisco.aci.aci_oob_epg_to_contract:
    epg: default
    state: query
  delegate_to: localhost

- name: Query a specific contract association with an out-of-band EPG
  cisco.aci.aci_oob_epg_to_contract:
    epg: default
    contract: default
    state: query
  delegate_to: localhost

- name: Remove contract association from an out-of-band EPG
  cisco.aci.aci_oob_epg_to_contract:
    epg: default
    contract: default
    state: absent
  delegate_to: localhost
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
     sample: class_map (30 bytes)
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
        epg=dict(type="str", required=True),
        contract=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["epg", "contract"]],
            ["state", "present", ["epg", "contract"]],
        ],
    )

    epg = module.params["epg"]
    contract = module.params["contract"]
    state = module.params["state"]

    ctProv_mo = "uni/tn-mgmt/oobbrc-{0}".format(contract)

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-mgmt",
            module_object="mgmt",
            target_filter={"name": "mgmt"},
        ),
        subclass_1=dict(
            aci_class="mgmtMgmtP",
            aci_rn="mgmtp-default",
            module_object="default",
            target_filter={"name": "default"},
        ),
        subclass_2=dict(
            aci_class="mgmtOoB",
            aci_rn="oob-{0}".format(epg),
            module_object=epg,
            target_filter={"name": epg},
        ),
        subclass_3=dict(
            aci_class="mgmtRsOoBProv",
            aci_rn="rsooBProv-{0}".format(contract),
            module_object=ctProv_mo if contract else None,
            target_filter={"tDn": ctProv_mo} if contract else {},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(aci_class="mgmtRsOoBProv", class_config=dict(tnVzOOBBrCPName=contract))

        aci.get_diff(aci_class="mgmtRsOoBProv")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
