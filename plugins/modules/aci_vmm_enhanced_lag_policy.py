#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# TODO in the documentation section mention the default values for lacp_mode, load_balancing_mode, number_uplinks
ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_vmm_enhanced_lag_policy
short_description: Manage Enhanced LACP Policy for Virtual Machine Manager (VMM) in Cisco ACI
description:
- Manage Enhanced LACP Policy (lacpEnhancedLagPol) for VMM domains on Cisco ACI fabrics.
- The Enhanced LACP Policy allows you to configure advanced Link Aggregation Control Protocol (LACP) settings for virtual switches in VMM domains.
- This policy is a child of the C(vmmVSwitchPolicyCont) class.

options:
  name:
    description:
    - The name of the Enhanced LACP Policy.
    type: str
    required: true
  domain:
    description:
    - The name of the virtual domain profile where the Enhanced LACP Policy is applied.
    type: str
    required: true
    aliases: [ domain_name, domain_profile ]
  vm_provider:
    description:
    - The virtualization platform provider for the VMM domain.
    type: str
    required: true
  lacp_mode:
    description:
    - The LACP mode for the policy.
    - Determines whether the policy initiates or responds to LACP negotiations.
    type: str
    choices: [ active, passive ]
    default: active
  load_balancing_mode:
    description:
    - The load balancing algorithm for distributing traffic across links in the port channel.
    - See the APIC Management Information Model reference for more details.
    type: str
    choices:
    - dst-ip
    - dst-ip-l4port
    - dst-ip-vlan
    - dst-ip-l4port-vlan
    - dst-mac
    - dst-l4port
    - src-ip
    - src-ip-l4port
    - src-ip-vlan
    - src-ip-l4port-vlan
    - src-mac
    - src-l4port
    - src-dst-ip
    - src-dst-ip-l4port
    - src-dst-ip-vlan
    - src-dst-ip-l4port-vlan
    - src-dst-mac
    - src-dst-l4port
    - src-port-id
    - vlan
    default: src-dst-ip
  number_uplinks:
    description:
    - The minimum number of uplinks required for the port channel.
    - Must be a value between 2 and 8.
    type: int
    default: 2
  state:
    description:
    - The desired state of the Enhanced LACP Policy.
    - Use C(present) to create or update the policy.
    - Use C(absent) to delete the policy.
    - Use C(query) to retrieve information about the policy.
    type: str
    choices: [ absent, present, query ]
    default: present

extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- module: cisco.aci.aci_domain
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(lacp:EnhancedLagPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Dev Sinha (@DevSinha13)
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    enhanced_lag_spec,
    netflow_spec,
)
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    aci_annotation_spec,
    aci_owner_spec,
)

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
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        #FIXME The problem could be that the argument is not recognized but if that is the case then how is the function not throwing an error.
        #1.)Try keeping the original function and changing the value here to false 
        #2.)Dont unpack the dictionary 
        #3.)Do what was done in vmm_vswitch_policy
        **enhanced_lag_spec(name_is_required=False),
        domain=dict(type="str", aliases=["domain_name", "domain_profile"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        vm_provider=dict(type="str", choices=list(VM_PROVIDER_MAPPING.keys())),
        # TODO Ensure that number of uplinks is added adequately
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "domain", "vm_provider"]],
            ["state", "present", ["name", "domain", "vm_provider"]],
        ],
    )

    name = module.params.get("name")
    lacp_mode = module.params.get("lacp_mode")
    load_balancing_mode = module.params.get("load_balancing_mode")
    number_uplinks = module.params.get("number_uplinks")
    domain = module.params.get("domain")
    state = module.params.get("state")
    vm_provider = module.params.get("vm_provider")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="vmmProvP",
            aci_rn="vmmp-{0}".format(VM_PROVIDER_MAPPING.get(vm_provider)),
            module_object=vm_provider,
            target_filter={"name": vm_provider},
        ),
        subclass_1=dict(
            aci_class="vmmDomP",
            aci_rn="dom-{0}".format(domain),
            module_object=domain,
            target_filter={"name": domain},
        ),
        subclass_2=dict(
            aci_class="vmmVSwitchPolicyCont",
            aci_rn="vswitchpolcont",
            module_object="vswitchpolcont",
            target_filter={"name": "vswitchpolcont"},
        ),
        subclass_3=dict(
            aci_class="lacpEnhancedLagPol",
            aci_rn="enlacplagp-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="lacpEnhancedLagPol",
            class_config=dict(
                name=name,
                mode=lacp_mode,
                lbmode=load_balancing_mode,
                numLinks=number_uplinks,
            ),
        )

        aci.get_diff(aci_class="lacpEnhancedLagPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()