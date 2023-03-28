#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Cindy Zhao <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_epg_to_contract_master
short_description: Manage End Point Group (EPG) contract master relationships (fv:RsSecInherited)
description:
- Manage End Point Groups (EPG) contract master relationships on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
    required: true
  ap:
    description:
    - Name of an existing application network profile, that will contain the EPGs.
    type: str
    required: true
    aliases: [ app_profile, app_profile_name ]
  epg:
    description:
    - Name of the end point group.
    type: str
    required: true
    aliases: [ epg_name, name ]
  contract_master_ap:
    description:
    - Name of the application profile where the contract master EPG is.
    type: str
  contract_master_epg:
    description:
    - Name of the end point group which serves as contract master.
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

notes:
- The C(tenant) and C(app_profile) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_ap) modules can be used for this.
seealso:
- module: cisco.aci.aci_epg
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:AEPg).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Cindy Zhao (@cizhao)
"""

EXAMPLES = r"""
- name: Add contract master
  cisco.aci.aci_epg_to_contract_master:
    host: apic_host
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: apName
    epg: epgName
    contract_master_ap: ap
    contract_master_epg: epg
    state: present
  delegate_to: localhost

- name: Remove contract master
  cisco.aci.aci_epg_to_contract_master:
    host: apic_host
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: apName
    epg: epgName
    contract_master_ap: ap
    contract_master_epg: epg
    state: absent
  delegate_to: localhost

- name: Query contract master
  cisco.aci.aci_epg_to_contract_master:
    host: apic_host
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: apName
    epg: epgName
    contract_master_ap: ap
    contract_master_epg: epg
    state: query
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
        tenant=dict(type="str", aliases=["tenant_name"], required=True),
        ap=dict(type="str", aliases=["app_profile", "app_profile_name"], required=True),
        epg=dict(type="str", aliases=["epg_name", "name"], required=True),
        contract_master_ap=dict(type="str"),
        contract_master_epg=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["contract_master_ap", "contract_master_epg"]],
            ["state", "present", ["contract_master_ap", "contract_master_epg"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    ap = module.params.get("ap")
    epg = module.params.get("epg")
    contract_master_ap = module.params.get("contract_master_ap")
    contract_master_epg = module.params.get("contract_master_epg")
    state = module.params.get("state")

    contract_master = "uni/tn-{0}/ap-{1}/epg-{2}".format(tenant, contract_master_ap, contract_master_epg)

    child_configs = []

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="fvAp",
            aci_rn="ap-{0}".format(ap),
            module_object=ap,
            target_filter={"name": ap},
        ),
        subclass_2=dict(
            aci_class="fvAEPg",
            aci_rn="epg-{0}".format(epg),
            module_object=epg,
            target_filter={"name": epg},
        ),
        subclass_3=dict(
            aci_class="fvRsSecInherited",
            aci_rn="rssecInherited-[{0}]".format(contract_master),
            module_object=contract_master,
            target_filter={"tDn": contract_master},
        ),
        child_classes=[],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(aci_class="fvRsSecInherited", class_config=dict(tDn=contract_master), child_configs=child_configs)

        aci.get_diff(aci_class="fvRsSecInherited")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
