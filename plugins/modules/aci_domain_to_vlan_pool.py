#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Dag Wieers <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_domain_to_vlan_pool
short_description: Bind Domain to VLAN Pools (infra:RsVlanNs)
description:
- Bind Domain to VLAN Pools on Cisco ACI fabrics.
options:
  domain:
    description:
    - Name of the domain being associated with the VLAN Pool.
    type: str
    aliases: [ domain_name, domain_profile ]
  domain_type:
    description:
    - Determines if the Domain is physical (phys) or virtual (vmm).
    type: str
    required: true
    choices: [ fc, l2dom, l3dom, phys, vmm ]
  pool:
    description:
    - The name of the pool.
    type: str
    aliases: [ pool_name, vlan_pool ]
  pool_allocation_mode:
    description:
    - The method used for allocating VLANs to resources.
    type: str
    required: true
    choices: [ dynamic, static]
    aliases: [ allocation_mode, mode ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  vm_provider:
    description:
    - The VM platform for VMM Domains.
    - Support for Kubernetes was added in ACI v3.0.
    - Support for CloudFoundry, OpenShift and Red Hat was added in ACI v3.1.
    type: str
    choices: [ cloudfoundry, kubernetes, microsoft, openshift, openstack, redhat, vmware ]
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- The C(domain) and C(vlan_pool) parameters should exist before using this module.
  The M(cisco.aci.aci_domain) and M(cisco.aci.aci_vlan_pool) can be used for these.
seealso:
- module: cisco.aci.aci_domain
- module: cisco.aci.aci_vlan_pool
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(infra:RsVlanNs).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Dag Wieers (@dagwieers)
"""

EXAMPLES = r"""
- name: Bind a VMM domain to VLAN pool
  cisco.aci.aci_domain_to_vlan_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: vmw_dom
    domain_type: vmm
    pool: vmw_pool
    pool_allocation_mode: dynamic
    vm_provider: vmware
    state: present
  delegate_to: localhost

- name: Remove a VMM domain to VLAN pool binding
  cisco.aci.aci_domain_to_vlan_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: vmw_dom
    domain_type: vmm
    pool: vmw_pool
    pool_allocation_mode: dynamic
    vm_provider: vmware
    state: absent
  delegate_to: localhost

- name: Bind a physical domain to VLAN pool
  cisco.aci.aci_domain_to_vlan_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: phys_dom
    domain_type: phys
    pool: phys_pool
    pool_allocation_mode: static
    state: present
  delegate_to: localhost

- name: Bind a physical domain to VLAN pool
  cisco.aci.aci_domain_to_vlan_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: phys_dom
    domain_type: phys
    pool: phys_pool
    pool_allocation_mode: static
    state: absent
  delegate_to: localhost

- name: Query an domain to VLAN pool binding
  cisco.aci.aci_domain_to_vlan_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: phys_dom
    domain_type: phys
    pool: phys_pool
    pool_allocation_mode: static
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all domain to VLAN pool bindings
  cisco.aci.aci_domain_to_vlan_pool:
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec

VM_PROVIDER_MAPPING = dict(
    cloudfoundry="CloudFoundry",
    kubernetes="Kubernetes",
    microsoft="Microsoft",
    openshift="OpenShift",
    openstack="OpenStack",
    redhat="Redhat",
    vmware="VMware",
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        domain_type=dict(type="str", required=True, choices=["fc", "l2dom", "l3dom", "phys", "vmm"]),
        domain=dict(type="str", aliases=["domain_name", "domain_profile"]),  # Not required for querying all objects
        pool=dict(type="str", aliases=["pool_name", "vlan_pool"]),  # Not required for querying all objects
        pool_allocation_mode=dict(type="str", required=True, aliases=["allocation_mode", "mode"], choices=["dynamic", "static"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        vm_provider=dict(type="str", choices=["cloudfoundry", "kubernetes", "microsoft", "openshift", "openstack", "redhat", "vmware"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["domain_type", "vmm", ["vm_provider"]],
            ["state", "absent", ["domain", "domain_type", "pool"]],
            ["state", "present", ["domain", "domain_type", "pool"]],
        ],
    )

    domain = module.params.get("domain")
    domain_type = module.params.get("domain_type")
    pool = module.params.get("pool")
    pool_allocation_mode = module.params.get("pool_allocation_mode")
    vm_provider = module.params.get("vm_provider")
    state = module.params.get("state")

    # Report when vm_provider is set when type is not virtual
    if domain_type != "vmm" and vm_provider is not None:
        module.fail_json(msg="Domain type '{0}' cannot have a 'vm_provider'".format(domain_type))

    # ACI Pool URL requires the allocation mode for vlan and vsan pools (ex: uni/infra/vlanns-[poolname]-static)
    pool_name = pool
    if pool is not None:
        pool_name = "[{0}]-{1}".format(pool, pool_allocation_mode)

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
        domain_mo = "uni/vmmp-{0}/dom-{1}".format(VM_PROVIDER_MAPPING[vm_provider], domain)
        domain_rn = "vmmp-{0}/dom-{1}".format(VM_PROVIDER_MAPPING[vm_provider], domain)

    # Ensure that querying all objects works when only domain_type is provided
    if domain is None:
        domain_mo = None

    aci_mo = "uni/infra/vlanns-{0}".format(pool_name)

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class=domain_class,
            aci_rn=domain_rn,
            module_object=domain_mo,
            target_filter={"name": domain},
        ),
        child_classes=["infraRsVlanNs"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=domain_class,
            class_config=dict(name=domain),
            child_configs=[
                {"infraRsVlanNs": {"attributes": {"tDn": aci_mo}}},
            ],
        )

        aci.get_diff(aci_class=domain_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
