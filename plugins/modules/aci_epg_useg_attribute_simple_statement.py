#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Christian Kolrep <christian.kolrep@dataport.de>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_epg_useg_attribute
short_description: Manage EPG useg Attributes
description:
- Manage VM Attributes in a microsegment EPG (fv:VmAttr)
- Manage IP Attributes in a microsegment EPG (fv:IpAttr)
- Manage MAC Attributes in a microsegment EPG (fv:MacAttr)
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  ap:
    description:
    - The name of an existing application network profile.
    type: str
    aliases: [ app_profile, app_profile_name ]
  epg:
    description:
    - The name of an existing end point group.
    type: str
    aliases: [ epg_name ]
  name:
    description:
    - The name of the EPG useg attribute.
    type: str
    aliases: [ useg_attribute_name ]
  type:
    description:
    - The type of the attribute
    type: str
    choices: [ ip, mac, vm_name, vm_guest, vm_host, vm_id, vmm_domain, vm_datacenter, vm_custom_attr, vm_tag, vm_nic ]
    aliases: [ useg_attribute_type ]
  operator:
    description:
    - The operator.
    - Required for most vm related attribute types.
    type: str
    choices: [ equals, contains, starts_with, ends_with ]
  category:
    description:
    - The name of the vmware tag category.
    - Required for type vm_tag.
    - The name of the vmware custom attribute.
    - Required for type vm_custom_attr.
    type: str
    aliases: [ custom_attribute ]
  use_subnet:
    description:
    - Use the EPG subnet definition for ip.
    - Used for type ip.
    - Mutualy exclusive with value
    type: str
    choices: [ 'yes', 'no' ]
  value:
    description:
    - The value of the useg attribute.
    type: str
  criterion:
    description:
    - List of existing sub criterions, representing the path to the sub criterion that will contain the useg attribute.
    - The order of the provided list matters, assuming the list ["A", "B", "C"].
    - Sub criterion A is chield of the default criterion, B is sub criterion of A and C is sub criterion of B.
    - default->A->B->C, the maximum depth of sub criterions is 3.
    - Empty list or None uses the default criterion of the EPG.
    type: list
    elements: str
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
- The I(tenant), I(ap) and I(epg) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_ap) and M(cisco.aci.aci_epg) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_ap
- module: cisco.aci.aci_epg
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:IpAttr) B(fv:MacAttr) B(fv:VmAttr).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Christian Kolrep (@Christian-Kolrep)
"""

EXAMPLES = r"""
- name: Add a new vmtag useg attribute for default criterion
  cisco.aci.aci_epg_useg_attribute:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    name: vmtagprod
    type: vmtag
    category: Environment
    operator: equals
    value: Production
    state: present
  delegate_to: localhost

- name: Remove an existing vmtag useg attribute from default criterion
  cisco.aci.aci_epg_useg_attribute:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    name: vmtagprod
    type: vmtag
    state: absent
  delegate_to: localhost

- name: Query a specific vmtag useg attribute in default criterion
  cisco.aci.aci_epg_useg_attribute:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    name: vmtagprod
    type: vmtag
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all vmtag useg attributes in default criterion
  cisco.aci.aci_epg_useg_attribute:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
    type: vmtag
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import USEG_ATTRIBUTE_MAPPING, OPERATOR_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        ap=dict(type="str", aliases=["app_profile", "app_profile_name"]),  # Not required for querying all objects
        epg=dict(type="str", aliases=["epg_name"]),  # Not required for querying all objects
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        criterion=dict(type="list", elements="str"),  # Criterion list
        name=dict(type="str", aliases=["useg_attribute_name"]),
        type=dict(type="str", choices=list(USEG_ATTRIBUTE_MAPPING.keys()), aliases=["useg_attribute_type"]),
        operator=dict(type="str", choices=list(OPERATOR_MAPPING.keys())),
        category=dict(type="str", aliases=["custom_attribute"]),
        value=dict(type="str"),
        use_subnet=dict(type="str", choices=["yes", "no"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["ap", "epg", "tenant", "name", "type"]],
            ["state", "present", ["ap", "epg", "tenant", "name", "type"]],
        ],
    )

    aci = ACIModule(module)

    ap = module.params.get("ap")
    epg = module.params.get("epg")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    criterion = module.params.get("criterion")
    useg_attr_name = module.params.get("name")
    useg_attr_type = module.params.get("type")
    useg_attr_value = module.params.get("value")
    useg_attr_operator = module.params.get("operator")
    useg_attr_category = module.params.get("category")
    useg_attr_use_subnet = module.params.get("use_subnet")

    #  useg attribute class and config
    attr_class = USEG_ATTRIBUTE_MAPPING[useg_attr_type]["attr_class"]
    attr_type = USEG_ATTRIBUTE_MAPPING[useg_attr_type]["attr_type"]
    attr_config = dict(name=useg_attr_name)

    if attr_class == "fvVmAttr":
        attr_rn = "vmattr-{0}".format(useg_attr_name)
        attr_config.update(type=attr_type)
        if useg_attr_value is not None:
            attr_config.update(value=useg_attr_value)
        if useg_attr_operator is not None:
            attr_config.update(operator=OPERATOR_MAPPING[useg_attr_operator])

        if useg_attr_type == "vm_custom_attr":
            if useg_attr_category is not None:
                attr_config.update(labelName=useg_attr_category)
        elif useg_attr_type == "vm_tag":
            if useg_attr_category is not None:
                attr_config.update(category=useg_attr_category)

    elif attr_class == "fvIpAttr":
        attr_rn = "ipattr-{0}".format(useg_attr_name)
        if useg_attr_use_subnet == "yes":
            attr_config.update(usefvSubnet=useg_attr_use_subnet)
        else:
            if useg_attr_value is not None:
                attr_config.update(ip=useg_attr_value)

    elif attr_class == "fvMacAttr":
        attr_rn = "macattr-{0}".format(useg_attr_name)
        if useg_attr_value is not None:
            attr_config.update(mac=useg_attr_value.upper())

    #  criterion class and building relative name
    crtrn_rn = "crtrn"
    crtrn_class = "fvCrtrn"
    crtrn_name = "default"
    if criterion:
        if len(criterion) > 3:
            module.fail_json(msg="Depth of sub criterion exceeds maximum limit 3.")
        crtrn_name = criterion[-1]
        crtrn_class = "fvSCrtrn"
        crtrn_rn = "crtrn/crtrn-" + "/crtrn-".join(criterion)

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
            aci_class=crtrn_class,
            aci_rn=crtrn_rn,
            module_object=crtrn_name,
            target_filter={"name": crtrn_name},
        ),
        subclass_4=dict(
            aci_class=attr_class,
            aci_rn=attr_rn,
            module_object=useg_attr_name,
            target_filter={"name": useg_attr_name},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(aci_class=attr_class, class_config=attr_config)

        aci.get_diff(aci_class=attr_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
