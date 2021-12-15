#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_l3out_extsubnet
short_description: Manage External Subnet objects (l3extSubnet:extsubnet)
description:
- Manage External Subnet objects (l3extSubnet:extsubnet)
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
    required: yes
  l3out:
    description:
    - Name of an existing L3Out.
    type: str
    aliases: [ l3out_name ]
    required: yes
  extepg:
    description:
    - Name of an existing ExtEpg.
    type: str
    aliases: [ extepg_name ]
    required: yes
  network:
    description:
    - The network address for the Subnet.
    type: str
    aliases: [ address, ip ]
  subnet_name:
    description:
    - Name of External Subnet being created.
    type: str
    aliases: [ name ]
  description:
    description:
    - Description for the External Subnet.
    type: str
    aliases: [ descr ]
  scope:
    description:
    - Determines the scope of the Subnet.
    - The C(export-rtctrl) option controls which external networks are advertised out of the fabric using route-maps and IP prefix-lists.
    - The C(import-security) option classifies for the external EPG.
      The rules and contracts defined in this external EPG apply to networks matching this subnet.
    - The C(shared-rtctrl) option controls which external prefixes are advertised to other tenants for shared services.
    - The C(shared-security) option configures the classifier for the subnets in the VRF where the routes are leaked.
    - The APIC defaults to C(import-security) when unset during creation.
    default: [ import-security ]
    type: list
    elements: str
    choices: [ export-rtctrl, import-security, shared-rtctrl, shared-security ]
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

notes:
- The C(tenant) and C(domain) and C(vrf) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_domain) and M(cisco.aci.aci_vrf) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_domain
- module: cisco.aci.aci_vrf
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l3ext:Out).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Rostyslav Davydenko (@rost-d)
- Cindy Zhao (@cizhao)
"""

EXAMPLES = r"""
- name: Add a new External Subnet
  cisco.aci.aci_l3out_extsubnet:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    l3out: prod_l3out
    extepg: prod_extepg
    description: External Subnet for Production ExtEpg
    network: 192.0.2.0/24
    scope: export-rtctrl
    state: present
  delegate_to: localhost

- name: Delete External Subnet
  cisco.aci.aci_l3out_extsubnet:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    l3out: prod_l3out
    extepg: prod_extepg
    network: 192.0.2.0/24
    state: absent
  delegate_to: localhost

- name: Query ExtEpg Subnet information
  cisco.aci.aci_l3out_extsubnet:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    l3out: prod_l3out
    extepg: prod_extepg
    network: 192.0.2.0/24
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
        tenant=dict(type="str", required=True, aliases=["tenant_name"]),
        l3out=dict(type="str", required=True, aliases=["l3out_name"]),
        extepg=dict(type="str", required=True, aliases=["extepg_name", "name"]),
        network=dict(type="str", aliases=["address", "ip"]),
        description=dict(type="str", aliases=["descr"]),
        subnet_name=dict(type="str", aliases=["name"]),
        scope=dict(type="list", elements="str", default=["import-security"], choices=["export-rtctrl", "import-security", "shared-rtctrl", "shared-security"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["network"]],
            ["state", "absent", ["network"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    extepg = module.params.get("extepg")
    network = module.params.get("network")
    description = module.params.get("description")
    subnet_name = module.params.get("subnet_name")
    scope = ",".join(sorted(module.params.get("scope")))
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

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
            aci_class="l3extSubnet",
            aci_rn="extsubnet-[{0}]".format(network),
            module_object=network,
            target_filter={"name": network},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="l3extSubnet",
            class_config=dict(
                ip=network,
                descr=description,
                name=subnet_name,
                scope=scope,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="l3extSubnet")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
