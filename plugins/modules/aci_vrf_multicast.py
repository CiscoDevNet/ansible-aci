#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Tim Cragg (@timcragg)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_vrf_multicast
short_description: Manage VRF Multicast objects (pim:CtxP).
description:
- Manage VRF Multicast objects on Cisco ACI fabrics.
- Creating this object enables Protocol Independent Multicast (PIM) on a VRF, and deleting it disables PIM on the VRF.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    required: yes
  vrf:
    description:
    - The name of an existing VRF.
    type: str
    required: yes
  mtu:
    description:
    - The MTU size supported for multicast.
    type: int
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
- The C(tenant) and C(vrf) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_vrf) modules can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fvTenant).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Enable Multicast on a VRF
  cisco.aci.aci_vrf_multicast:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    vrf: ansible_vrf
    mtu: 2000
    state: present
    delegate_to: localhost

- name: Disable Multicast on a VRF
  cisco.aci.aci_vrf_multicast:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    vrf: ansible_vrf
    state: absent
    delegate_to: localhost

- name: Query Multicast Settings on a VRF
  cisco.aci.aci_vrf_multicast:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    vrf: ansible_vrf
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


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", required=True),
        vrf=dict(type="str", required=True),
        mtu=dict(type="int"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    tenant = module.params.get("tenant")
    vrf = module.params.get("vrf")
    mtu = module.params.get("mtu")
    state = module.params.get("state")

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
        subclass_2=dict(
            aci_class="pimCtxP",
            aci_rn="pimctxp",
            module_object=None,
            target_filter=None,
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="pimCtxP",
            class_config=dict(
                mtu=mtu,
            ),
        )

        aci.get_diff(aci_class="pimCtxP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
