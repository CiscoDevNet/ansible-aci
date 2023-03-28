#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_domain
short_description: Manage physical, virtual, bridged, routed or FC domain profiles (phys:DomP, vmm:DomP, l2ext:DomP, l3ext:DomP, fc:DomP)
description:
- Manage physical, virtual, bridged, routed or FC domain profiles on Cisco ACI fabrics.
options:
  domain:
    description:
    - Name of the physical, virtual, bridged routed or FC domain profile.
    type: str
    aliases: [ domain_name, domain_profile, name ]
  domain_type:
    description:
    - The type of domain profile.
    - 'C(fc): The FC domain profile is a policy pertaining to single FC Management domain'
    - 'C(l2dom): The external bridged domain profile is a policy for managing L2 bridged infrastructure bridged outside the fabric.'
    - 'C(l3dom): The external routed domain profile is a policy for managing L3 routed infrastructure outside the fabric.'
    - 'C(phys): The physical domain profile stores the physical resources and encap resources that should be used for EPGs associated with this domain.'
    - 'C(vmm): The VMM domain profile is a policy for grouping VM controllers with similar networking policy requirements.'
    type: str
    required: true
    choices: [ fc, l2dom, l3dom, phys, vmm ]
    aliases: [ type ]
  dscp:
    description:
    - The target Differentiated Service (DSCP) value.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43, CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, unspecified ]
    aliases: [ target ]
  encap_mode:
    description:
    - The layer 2 encapsulation protocol to use with the virtual switch.
    type: str
    choices: [ unknown, vlan, vxlan ]
  add_infra_pg:
    description:
    - Configure port groups for infra VLAN (e.g. Virtual APIC).
    type: bool
    aliases: [ infra_pg ]
  tag_collection:
    description:
    - Enables Cisco APIC to collect VMs that have been assigned tags in VMware vCenter for microsegmentation.
    type: bool
  multicast_address:
    description:
    - The multicast IP address to use for the virtual switch.
    type: str
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
  vm_provider:
    description:
    - The VM platform for VMM Domains.
    - Support for Kubernetes was added in ACI v3.0.
    - Support for CloudFoundry, OpenShift and Red Hat was added in ACI v3.1.
    type: str
    choices: [ cloudfoundry, kubernetes, microsoft, openshift, openstack, redhat, vmware ]
  vswitch:
    description:
    - The virtual switch to use for vmm domains.
    - The APIC defaults to C(default) when unset during creation.
    type: str
    choices: [ avs, default, dvs, unknown ]
  access_mode:
    description:
    - Access mode for vmm domains
    - This parameter cannot be changed after a domain is created
    type: str
    choices: [ read-only, read-write ]
  enable_vm_folder:
    description:
    - Enable VM folder data retrieval
    type: bool
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- module: cisco.aci.aci_aep_to_domain
- module: cisco.aci.aci_domain_to_encap_pool
- module: cisco.aci.aci_domain_to_vlan_pool
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(phys:DomP),
               B(vmm:DomP), B(l2ext:DomP), B(l3ext:DomP) and B(fc:DomP)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Dag Wieers (@dagwieers)
"""

EXAMPLES = r"""
- name: Add a new physical domain
  cisco.aci.aci_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: phys_dom
    domain_type: phys
    state: present

- name: Remove a physical domain
  cisco.aci.aci_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: phys_dom
    domain_type: phys
    state: absent

- name: Add a new VMM domain
  cisco.aci.aci_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: hyperv_dom
    domain_type: vmm
    vm_provider: microsoft
    state: present
  delegate_to: localhost

- name: Remove a VMM domain
  cisco.aci.aci_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: hyperv_dom
    domain_type: vmm
    vm_provider: microsoft
    state: absent
  delegate_to: localhost

- name: Query a specific physical domain
  cisco.aci.aci_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: phys_dom
    domain_type: phys
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all domains
  cisco.aci.aci_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain_type: phys
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

VM_PROVIDER_MAPPING = dict(
    cloudfoundry="CloudFoundry",
    kubernetes="Kubernetes",
    microsoft="Microsoft",
    openshift="OpenShift",
    openstack="OpenStack",
    redhat="Redhat",
    vmware="VMware",
)

VSWITCH_MAPPING = dict(
    avs="n1kv",
    default="default",
    dvs="default",
    unknown="unknown",
)

BOOL_TO_ACI_MAPPING = {True: "yes", False: "no", None: None}


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        domain_type=dict(type="str", required=True, choices=["fc", "l2dom", "l3dom", "phys", "vmm"], aliases=["type"]),
        domain=dict(type="str", aliases=["domain_name", "domain_profile", "name"]),  # Not required for querying all objects
        dscp=dict(
            type="str",
            choices=[
                "AF11",
                "AF12",
                "AF13",
                "AF21",
                "AF22",
                "AF23",
                "AF31",
                "AF32",
                "AF33",
                "AF41",
                "AF42",
                "AF43",
                "CS0",
                "CS1",
                "CS2",
                "CS3",
                "CS4",
                "CS5",
                "CS6",
                "CS7",
                "EF",
                "VA",
                "unspecified",
            ],
            aliases=["target"],
        ),
        encap_mode=dict(type="str", choices=["unknown", "vlan", "vxlan"]),
        add_infra_pg=dict(type="bool", aliases=["infra_pg"]),
        tag_collection=dict(type="bool"),
        multicast_address=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        vm_provider=dict(type="str", choices=["cloudfoundry", "kubernetes", "microsoft", "openshift", "openstack", "redhat", "vmware"]),
        vswitch=dict(type="str", choices=["avs", "default", "dvs", "unknown"]),
        name_alias=dict(type="str"),
        access_mode=dict(type="str", choices=["read-write", "read-only"]),
        enable_vm_folder=dict(type="bool"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["domain_type", "vmm", ["vm_provider"]],
            ["state", "absent", ["domain", "domain_type"]],
            ["state", "present", ["domain", "domain_type"]],
        ],
    )

    dscp = module.params.get("dscp")
    domain = module.params.get("domain")
    domain_type = module.params.get("domain_type")
    encap_mode = module.params.get("encap_mode")
    add_infra_pg = BOOL_TO_ACI_MAPPING[module.params.get("add_infra_pg")]
    tag_collection = BOOL_TO_ACI_MAPPING[module.params.get("tag_collection")]
    multicast_address = module.params.get("multicast_address")
    vm_provider = module.params.get("vm_provider")
    vswitch = module.params.get("vswitch")
    if vswitch is not None:
        vswitch = VSWITCH_MAPPING.get(vswitch)
    access_mode = module.params.get("access_mode")
    enable_vm_folder = BOOL_TO_ACI_MAPPING[module.params.get("enable_vm_folder")]
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    if domain_type != "vmm":
        if vm_provider is not None:
            module.fail_json(msg="Domain type '{0}' cannot have parameter 'vm_provider'".format(domain_type))
        if encap_mode is not None:
            module.fail_json(msg="Domain type '{0}' cannot have parameter 'encap_mode'".format(domain_type))
        if multicast_address is not None:
            module.fail_json(msg="Domain type '{0}' cannot have parameter 'multicast_address'".format(domain_type))
        if vswitch is not None:
            module.fail_json(msg="Domain type '{0}' cannot have parameter 'vswitch'".format(domain_type))
        if access_mode is not None:
            module.fail_json(msg="Domain type '{0}' cannot have parameter 'access_mode'".format(domain_type))
        if enable_vm_folder is not None:
            module.fail_json(msg="Domain type '{0}' cannot have parameter 'enable_vm_folder'".format(domain_type))

    if dscp is not None and domain_type not in ["l2dom", "l3dom"]:
        module.fail_json(msg="DSCP values can only be assigned to 'l2ext and 'l3ext' domains")

    # Compile the full domain for URL building
    if domain_type == "fc":
        domain_class = "fcDomP"
        domain_mo = "uni/fc-{0}".format(domain)
        domain_rn = "fc-{0}".format(domain)
    elif domain_type == "l2dom":
        domain_class = "l2extDomP"
        domain_mo = "uni/l2dom-{0}".format(domain)
        domain_rn = "l2dom-{0}".format(domain)
    elif domain_type == "l3dom":
        domain_class = "l3extDomP"
        domain_mo = "uni/l3dom-{0}".format(domain)
        domain_rn = "l3dom-{0}".format(domain)
    elif domain_type == "phys":
        domain_class = "physDomP"
        domain_mo = "uni/phys-{0}".format(domain)
        domain_rn = "phys-{0}".format(domain)
    elif domain_type == "vmm":
        domain_class = "vmmDomP"
        domain_mo = "uni/vmmp-{0}/dom-{1}".format(VM_PROVIDER_MAPPING.get(vm_provider), domain)
        domain_rn = "vmmp-{0}/dom-{1}".format(VM_PROVIDER_MAPPING.get(vm_provider), domain)

    # Ensure that querying all objects works when only domain_type is provided
    if domain is None:
        domain_mo = None

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class=domain_class,
            aci_rn=domain_rn,
            module_object=domain_mo,
            target_filter={"name": domain},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=domain_class,
            class_config=dict(
                encapMode=encap_mode,
                mcastAddr=multicast_address,
                configInfraPg=add_infra_pg,
                enableTag=tag_collection,
                mode=vswitch,
                name=domain,
                targetDscp=dscp,
                nameAlias=name_alias,
                accessMode=access_mode,
                enableVmFolder=enable_vm_folder,
            ),
        )

        aci.get_diff(aci_class=domain_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
