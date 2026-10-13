#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Dag Wieers <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_domain_to_encap_pool
short_description: Bind Domain to Encap Pools (infra:RsVlanNs)
description:
- Bind Domain to Encap Pools on Cisco ACI fabrics.
notes:
- The C(domain) and C(encap_pool) parameters should exist before using this module.
  The M(cisco.aci.aci_domain) and M(cisco.aci.aci_encap_pool) can be used for these.
options:
  domain:
    description:
    - Name of the domain being associated with the Encap Pool.
    type: str
    aliases: [ domain_name, domain_profile ]
  domain_type:
    description:
    - Domain type to use for the binding.
    - Required when creating or removing a binding, or when querying a specific domain.
    - Optional for a query without C(domain), where it filters results to the selected domain type.
    type: str
    choices: [ fc, l2dom, l3dom, phys, vmm ]
  pool:
    description:
    - The name of the pool.
    type: str
    aliases: [ pool_name ]
  pool_allocation_mode:
    description:
    - The method used for allocating encaps to resources.
    - Only vlan and vsan support allocation modes.
    type: str
    choices: [ dynamic, static]
    aliases: [ allocation_mode, mode ]
  pool_type:
    description:
    - The encap type of C(pool).
    type: str
    required: true
    choices: [ vlan, vsan, vxlan ]
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
    - Optional when querying all VMM domains; omit to include every provider.
    - Support for Kubernetes was added in ACI v3.0.
    - Support for CloudFoundry, OpenShift and Red Hat was added in ACI v3.1.
    type: str
    choices: [ cloudfoundry, kubernetes, microsoft, openshift, openstack, redhat, vmware, nutanix ]
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

seealso:
- module: cisco.aci.aci_domain
- module: cisco.aci.aci_encap_pool
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(infra:RsVlanNs).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Dag Wieers (@dagwieers)
"""

EXAMPLES = r"""
- name: Add domain to VLAN pool binding
  cisco.aci.aci_domain_to_encap_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: phys_dom
    domain_type: phys
    pool: test_pool
    pool_type: vlan
    pool_allocation_mode: dynamic
    state: present
  delegate_to: localhost

- name: Remove domain to VLAN pool binding
  cisco.aci.aci_domain_to_encap_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: phys_dom
    domain_type: phys
    pool: test_pool
    pool_type: vlan
    pool_allocation_mode: dynamic
    state: absent
  delegate_to: localhost

- name: Query our domain to VLAN pool binding
  cisco.aci.aci_domain_to_encap_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: phys_dom
    domain_type: phys
    pool: test_pool
    pool_type: vlan
    pool_allocation_mode: dynamic
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all domain to VLAN pool bindings
  cisco.aci.aci_domain_to_encap_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    pool_type: vlan
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all physical domain to VLAN pool bindings
  cisco.aci.aci_domain_to_encap_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain_type: phys
    pool_type: vlan
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all VMM domain to VLAN pool bindings across providers
  cisco.aci.aci_domain_to_encap_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain_type: vmm
    pool_type: vlan
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import VM_PROVIDER_MAPPING

POOL_MAPPING = dict(
    vlan=dict(
        aci_mo="uni/infra/vlanns-{0}",
        class_name="infraRsVlanNs",
        class_rn="rsvlanNs",
    ),
    vxlan=dict(
        aci_mo="uni/infra/vxlanns-{0}",
        class_name="vmmRsVxlanNs",
        class_rn="rsvxlanNs",
    ),
    vsan=dict(
        aci_mo="uni/infra/vsanns-{0}",
        class_name="fcRsVsanNs",
        class_rn="rsvsanNs",
    ),
)

DOMAIN_MAPPING = dict(
    fc=dict(
        domain_class="fcDomP",
        domain_mo="uni/fc-{domain}",
        domain_rn="fc-{domain}",
        domain_dn_filter="uni/fc-.*",
    ),
    l2dom=dict(
        domain_class="l2extDomP",
        domain_mo="uni/l2dom-{domain}",
        domain_rn="l2dom-{domain}",
        domain_dn_filter="uni/l2dom-.*",
    ),
    l3dom=dict(
        domain_class="l3extDomP",
        domain_mo="uni/l3dom-{domain}",
        domain_rn="l3dom-{domain}",
        domain_dn_filter="uni/l3dom-.*",
    ),
    phys=dict(
        domain_class="physDomP",
        domain_mo="uni/phys-{domain}",
        domain_rn="phys-{domain}",
        domain_dn_filter="uni/phys-.*",
    ),
    vmm=dict(
        domain_class="vmmDomP",
        domain_mo="uni/vmmp-{provider}/dom-{domain}",
        domain_rn="vmmp-{provider}/dom-{domain}",
        domain_dn_filter="uni/vmmp-{provider}/dom-.*",
    ),
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        pool_type=dict(type="str", required=True, choices=["vlan", "vsan", "vxlan"]),
        domain_type=dict(type="str", choices=["fc", "l2dom", "l3dom", "phys", "vmm"]),  # Not required for querying all objects
        domain=dict(type="str", aliases=["domain_name", "domain_profile"]),  # Not required for querying all objects
        pool=dict(type="str", aliases=["pool_name"]),  # Not required for querying all objects
        pool_allocation_mode=dict(type="str", aliases=["allocation_mode", "mode"], choices=["dynamic", "static"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        vm_provider=dict(type="str", choices=list(VM_PROVIDER_MAPPING)),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["domain", "pool"]],
            ["state", "present", ["domain", "pool"]],
        ],
        required_by={"domain": "domain_type"},
    )

    domain = module.params.get("domain")
    domain_type = module.params.get("domain_type")
    pool = module.params.get("pool")
    pool_allocation_mode = module.params.get("pool_allocation_mode")
    pool_type = module.params.get("pool_type")
    vm_provider = module.params.get("vm_provider")
    state = module.params.get("state")

    # Provider is needed to address a specific VMM domain, but query-all can
    # cover every VMM provider unless the caller chooses to narrow it.
    if domain_type == "vmm" and vm_provider is None and not (state == "query" and domain is None):
        module.fail_json(msg="'vm_provider' is required for a VMM domain type")

    # Report when vm_provider is set when type is not virtual
    if domain_type != "vmm" and vm_provider is not None:
        module.fail_json(msg="Domain type '{0}' cannot have a 'vm_provider'".format(domain_type))

    # ACI Pool URL requires the allocation mode for vlan and vsan pools (ex: uni/infra/vlanns-[poolname]-static)
    pool_name = pool
    if pool_type != "vxlan" and pool is not None:
        if pool_allocation_mode is not None:
            pool_name = "[{0}]-{1}".format(pool, pool_allocation_mode)
        else:
            module.fail_json(msg="ACI requires the 'pool_allocation_mode' for 'pool_type' of 'vlan' and 'vsan' when 'pool' is provided")

    # Vxlan pools do not support allocation modes
    if pool_type == "vxlan" and pool_allocation_mode is not None:
        module.fail_json(msg="vxlan pools do not support setting the allocation_mode; please remove this parameter from the task")

    # Compile the domain only when its type is known. The unfiltered query-all
    # path does not need a parent domain class or DN.
    domain_mapping = DOMAIN_MAPPING.get(domain_type)

    domain_format_values = {"domain": domain}
    if domain_type == "vmm":
        domain_format_values["provider"] = ".*" if vm_provider is None else VM_PROVIDER_MAPPING[vm_provider]

    pool_mo = POOL_MAPPING[pool_type]["aci_mo"].format(pool_name)
    class_name = POOL_MAPPING[pool_type]["class_name"]

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class=domain_mapping["domain_class"] if domain_mapping else None,
            aci_rn=domain_mapping["domain_rn"].format(**domain_format_values) if domain_mapping and domain is not None else None,
            module_object=domain_mapping["domain_mo"].format(**domain_format_values) if domain_mapping and domain is not None else None,
            target_filter={"name": domain},
        ),
        subclass_1=dict(
            aci_class=class_name,
            aci_rn=POOL_MAPPING[pool_type]["class_rn"],
            module_object=pool_mo if pool is not None else None,
            target_filter={"tDn": pool_mo} if pool is not None else {},
        ),
    )

    # A query for one domain is already scoped to that domain's DN by construct_url.
    # Query-all uses a class endpoint instead, so filter the relationship objects by
    # the parent domain path in their DN when domain_type is provided.
    if state == "query" and domain is None and domain_type is not None:
        # construct_url may already have added a pool query filter.
        # update_qs appends parameters, clear it before adding the combined pool and domain-type filter.
        aci.filter_string = ""

        query_filters = ['wcard({0}.dn,"{1}")'.format(class_name, domain_mapping["domain_dn_filter"].format(**domain_format_values))]
        if pool is not None:
            query_filters.insert(0, aci.build_filter(class_name, {"tDn": pool_mo}))

        # Build the final query filter from scratch to avoid duplicate
        # query-target-filter parameters from construct_url.
        aci.update_qs({"query-target-filter": query_filters[0] if len(query_filters) == 1 else "and({0})".format(",".join(query_filters))})

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=class_name,
            class_config=dict(tDn=pool_mo),
        )

        aci.get_diff(aci_class=class_name)

        # Submit changes if module not in check_mode and the proposed is different than existing
        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
