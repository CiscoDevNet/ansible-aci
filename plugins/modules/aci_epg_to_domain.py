#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Jacob McGill <jmcgill298>
# Copyright: (c) 2020, Shreyas Srish <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
---
module: aci_epg_to_domain
short_description: Bind EPGs to Domains (fv:RsDomAtt)
description:
- Bind EPGs to Physical and Virtual Domains on Cisco ACI fabrics.
options:
  allow_useg:
    description:
    - Allows micro-segmentation.
    - The APIC defaults to C(encap) when unset during creation.
    type: str
    choices: [ encap, useg ]
  ap:
    description:
    - Name of an existing application network profile, that will contain the EPGs.
    type: str
    aliases: [ app_profile, app_profile_name ]
  deploy_immediacy:
    description:
    - Determines when the policy is pushed to hardware Policy CAM.
    - The APIC defaults to C(lazy) when unset during creation.
    type: str
    choices: [ immediate, lazy ]
  domain:
    description:
    - Name of the physical or virtual domain being associated with the EPG.
    type: str
    aliases: [ domain_name, domain_profile ]
  domain_type:
    description:
    - Specify whether the Domain is a physical (phys), a virtual (vmm) or an L2 external domain association (l2dom).
    type: str
    choices: [ l2dom, phys, vmm ]
    aliases: [ type ]
  encap:
    description:
    - The VLAN encapsulation for the EPG when binding a VMM Domain with static C(encap_mode).
    - This acts as the secondary encap when using useg.
    - Accepted values range between C(1) and C(4096).
    type: int
  encap_mode:
    description:
    - The encapsulation method to be used.
    - The APIC defaults to C(auto) when unset during creation.
    - If vxlan is selected, switching_mode must be "AVE".
    type: str
    choices: [ auto, vlan, vxlan ]
  switching_mode:
    description:
    - Switching Mode used by the switch
    type: str
    choices: [ AVE, native ]
    default: native
  epg:
    description:
    - Name of the end point group.
    type: str
    aliases: [ epg_name, name ]
  netflow:
    description:
    - Determines if netflow should be enabled.
    - The APIC defaults to C(no) when unset during creation.
    type: bool
  primary_encap:
    description:
    - Determines the primary VLAN ID when using useg.
    - Accepted values range between C(1) and C(4096).
    type: int
  resolution_immediacy:
    description:
    - Determines when the policies should be resolved and available.
    - The APIC defaults to C(lazy) when unset during creation.
    type: str
    choices: [ immediate, lazy, pre-provision ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  promiscuous:
    description:
    - Allow/Disallow promiscuous mode in vmm domain
    type: str
    choices: [ accept, reject ]
    default: reject
  vm_provider:
    description:
    - The VM platform for VMM Domains.
    - Support for Kubernetes was added in ACI v3.0.
    - Support for CloudFoundry, OpenShift and Red Hat was added in ACI v3.1.
    type: str
    choices: [ cloudfoundry, kubernetes, microsoft, openshift, openstack, redhat, vmware ]
extends_documentation_fragment:
- cisco.aci.aci

notes:
- The C(tenant), C(ap), C(epg), and C(domain) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) M(cisco.aci.aci_ap), M(cisco.aci.aci_epg) M(cisco.aci.aci_domain) modules can be used for this.
- OpenStack VMM domains must not be created using this module. The OpenStack VMM domain is created directly
  by the Cisco APIC Neutron plugin as part of the installation and configuration.
  This module can be used to query status of an OpenStack VMM domain.
seealso:
- module: cisco.aci.aci_ap
- module: cisco.aci.aci_epg
- module: cisco.aci.aci_domain
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:RsDomAtt).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Jacob McGill (@jmcgill298)
- Shreyas Srish (@shrsr)
'''

EXAMPLES = r'''
- name: Add a new physical domain to EPG binding
  cisco.aci.aci_epg_to_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    domain: anstest
    domain_type: phys
    state: present
  delegate_to: localhost

- name: Remove an existing physical domain to EPG binding
  cisco.aci.aci_epg_to_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    domain: anstest
    domain_type: phys
    state: absent
  delegate_to: localhost

- name: Query a specific physical domain to EPG binding
  cisco.aci.aci_epg_to_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    domain: anstest
    domain_type: phys
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all domain to EPG bindings
  cisco.aci.aci_epg_to_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result
'''

RETURN = r'''
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
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec

VM_PROVIDER_MAPPING = dict(
    cloudfoundry='CloudFoundry',
    kubernetes='Kubernetes',
    microsoft='Microsoft',
    openshift='OpenShift',
    openstack='OpenStack',
    redhat='Redhat',
    vmware='VMware',
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        allow_useg=dict(type='str', choices=['encap', 'useg']),
        ap=dict(type='str', aliases=['app_profile', 'app_profile_name']),  # Not required for querying all objects
        deploy_immediacy=dict(type='str', choices=['immediate', 'lazy']),
        domain=dict(type='str', aliases=['domain_name', 'domain_profile']),  # Not required for querying all objects
        domain_type=dict(type='str', choices=['l2dom', 'phys', 'vmm'], aliases=['type']),  # Not required for querying all objects
        encap=dict(type='int'),
        encap_mode=dict(type='str', choices=['auto', 'vlan', 'vxlan']),
        switching_mode=dict(type='str', default='native', choices=['AVE', 'native']),
        epg=dict(type='str', aliases=['name', 'epg_name']),  # Not required for querying all objects
        netflow=dict(type='bool'),
        primary_encap=dict(type='int'),
        resolution_immediacy=dict(type='str', choices=['immediate', 'lazy', 'pre-provision']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
        tenant=dict(type='str', aliases=['tenant_name']),  # Not required for querying all objects
        vm_provider=dict(type='str', choices=['cloudfoundry', 'kubernetes', 'microsoft', 'openshift', 'openstack', 'redhat', 'vmware']),
        promiscuous=dict(type='str', default='reject', choices=['accept', 'reject']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['domain_type', 'vmm', ['vm_provider']],
            ['state', 'absent', ['ap', 'domain', 'domain_type', 'epg', 'tenant']],
            ['state', 'present', ['ap', 'domain', 'domain_type', 'epg', 'tenant']],
        ],
    )

    aci = ACIModule(module)

    allow_useg = module.params.get('allow_useg')
    ap = module.params.get('ap')
    deploy_immediacy = module.params.get('deploy_immediacy')
    domain = module.params.get('domain')
    domain_type = module.params.get('domain_type')
    vm_provider = module.params.get('vm_provider')
    promiscuous = module.params.get('promiscuous')
    encap = module.params.get('encap')
    if encap is not None:
        if encap in range(1, 4097):
            encap = 'vlan-{0}'.format(encap)
        else:
            module.fail_json(msg='Valid VLAN assignments are from 1 to 4096')
    encap_mode = module.params.get('encap_mode')
    switching_mode = module.params.get('switching_mode')
    epg = module.params.get('epg')
    netflow = aci.boolean(module.params.get('netflow'), 'enabled', 'disabled')
    primary_encap = module.params.get('primary_encap')
    if primary_encap is not None:
        if primary_encap in range(1, 4097):
            primary_encap = 'vlan-{0}'.format(primary_encap)
        else:
            module.fail_json(msg='Valid VLAN assignments are from 1 to 4096')
    resolution_immediacy = module.params.get('resolution_immediacy')
    state = module.params.get('state')
    tenant = module.params.get('tenant')

    if domain_type in ['l2dom', 'phys'] and vm_provider is not None:
        module.fail_json(msg="Domain type '%s' cannot have a 'vm_provider'" % domain_type)

    child_classes = None
    child_configs = None

    # Compile the full domain for URL building
    if domain_type == 'vmm':
        epg_domain = 'uni/vmmp-{0}/dom-{1}'.format(VM_PROVIDER_MAPPING[vm_provider], domain)
        child_configs = [dict(vmmSecP=dict(attributes=dict(allowPromiscuous=promiscuous)))]
        child_classes = ['vmmSecP']
    elif domain_type == 'l2dom':
        epg_domain = 'uni/l2dom-{0}'.format(domain)
    elif domain_type == 'phys':
        epg_domain = 'uni/phys-{0}'.format(domain)
    else:
        epg_domain = None

    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant},
        ),
        subclass_1=dict(
            aci_class='fvAp',
            aci_rn='ap-{0}'.format(ap),
            module_object=ap,
            target_filter={'name': ap},
        ),
        subclass_2=dict(
            aci_class='fvAEPg',
            aci_rn='epg-{0}'.format(epg),
            module_object=epg,
            target_filter={'name': epg},
        ),
        subclass_3=dict(
            aci_class='fvRsDomAtt',
            aci_rn='rsdomAtt-[{0}]'.format(epg_domain),
            module_object=epg_domain,
            target_filter={'tDn': epg_domain},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='fvRsDomAtt',
            class_config=dict(
                classPref=allow_useg,
                encap=encap,
                encapMode=encap_mode,
                switchingMode=switching_mode,
                instrImedcy=deploy_immediacy,
                netflowPref=netflow,
                primaryEncap=primary_encap,
                resImedcy=resolution_immediacy,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class='fvRsDomAtt')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
