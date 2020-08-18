#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
---
module: aci_l3out
short_description: Manage Layer 3 Outside (L3Out) objects (l3ext:Out)
description:
- Manage Layer 3 Outside (L3Out) on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l3out:
    description:
    - Name of L3Out being created.
    type: str
    aliases: [ l3out_name, name ]
  vrf:
    description:
    - Name of the VRF being associated with the L3Out.
    type: str
    aliases: [ vrf_name ]
  domain:
    description:
    - Name of the external L3 domain being associated with the L3Out.
    type: str
    aliases: [ ext_routed_domain_name, routed_domain ]
  dscp:
    description:
    - The target Differentiated Service (DSCP) value.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43, CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, unspecified ]
    aliases: [ target ]
  route_control:
    description:
    - Route Control enforcement direction. The only allowed values are export or import,export.
    type: list
    elements: str
    choices: [ export, import ]
    aliases: [ route_control_enforcement ]
  l3protocol:
    description:
    - Routing protocol for the L3Out
    type: list
    elements: str
    choices: [ bgp, eigrp, ospf, pim, static ]
  asn:
    description:
    - The AS number for the L3Out.
    - Only applicable when using 'eigrp' as the l3protocol
    type: int
    aliases: [ as_number ]
  description:
    description:
    - Description for the L3Out.
    type: str
    aliases: [ descr ]
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
'''

EXAMPLES = r'''
- name: Add a new L3Out
  cisco.aci.aci_l3out:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    name: prod_l3out
    description: L3Out for Production tenant
    domain: l3dom_prod
    vrf: prod
    l3protocol: ospf
    state: present
  delegate_to: localhost

- name: Delete L3Out
  cisco.aci.aci_l3out:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    name: prod_l3out
    state: absent
  delegate_to: localhost

- name: Query L3Out information
  cisco.aci.aci_l3out:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    name: prod_l3out
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


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        tenant=dict(type='str', aliases=['tenant_name']),  # Not required for querying all objects
        l3out=dict(type='str', aliases=['l3out_name', 'name']),  # Not required for querying all objects
        domain=dict(type='str', aliases=['ext_routed_domain_name', 'routed_domain']),
        vrf=dict(type='str', aliases=['vrf_name']),
        description=dict(type='str', aliases=['descr']),
        route_control=dict(type='list', elements='str', choices=['export', 'import'], aliases=['route_control_enforcement']),
        dscp=dict(type='str',
                  choices=['AF11', 'AF12', 'AF13', 'AF21', 'AF22', 'AF23', 'AF31', 'AF32', 'AF33', 'AF41', 'AF42',
                           'AF43', 'CS0', 'CS1', 'CS2', 'CS3', 'CS4', 'CS5', 'CS6', 'CS7', 'EF', 'VA', 'unspecified'],
                  aliases=['target']),
        l3protocol=dict(type='list', elements='str', choices=['bgp', 'eigrp', 'ospf', 'pim', 'static']),
        asn=dict(type='int', aliases=['as_number']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
        name_alias=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['l3out', 'tenant']],
            ['state', 'present', ['l3out', 'tenant', 'domain', 'vrf']],
        ],
    )

    aci = ACIModule(module)

    l3out = module.params.get('l3out')
    domain = module.params.get('domain')
    dscp = module.params.get('dscp')
    description = module.params.get('description')
    enforceRtctrl = module.params.get('route_control')
    vrf = module.params.get('vrf')
    l3protocol = module.params.get('l3protocol')
    asn = module.params.get('asn')
    state = module.params.get('state')
    tenant = module.params.get('tenant')
    name_alias = module.params.get('name_alias')

    if l3protocol:
        if 'eigrp' in l3protocol and asn is None:
            module.fail_json(msg="Parameter 'asn' is required when l3protocol is 'eigrp'")
        if 'eigrp' not in l3protocol and asn is not None:
            module.warn("Parameter 'asn' is only applicable when l3protocol is 'eigrp'. The ASN will be ignored")

    enforce_ctrl = ''
    if enforceRtctrl is not None:
        if len(enforceRtctrl) == 1 and enforceRtctrl[0] == 'import':
            aci.fail_json(
                "The route_control parameter is invalid: allowed options are export or import,export only")
        elif len(enforceRtctrl) == 1 and enforceRtctrl[0] == 'export':
            enforce_ctrl = 'export'
        else:
            enforce_ctrl = 'export,import'
    child_classes = ['l3extRsL3DomAtt', 'l3extRsEctx', 'bgpExtP', 'ospfExtP', 'eigrpExtP', 'pimExtP']

    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant},
        ),
        subclass_1=dict(
            aci_class='l3extOut',
            aci_rn='out-{0}'.format(l3out),
            module_object=l3out,
            target_filter={'name': l3out},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    child_configs = [
        dict(l3extRsL3DomAtt=dict(attributes=dict(
            tDn='uni/l3dom-{0}'.format(domain)))),
        dict(l3extRsEctx=dict(attributes=dict(tnFvCtxName=vrf))),
    ]
    if l3protocol is not None:
        for protocol in l3protocol:
            if protocol == 'bgp':
                child_configs.append(
                    dict(bgpExtP=dict(attributes=dict(descr='', nameAlias=''))))
            elif protocol == 'eigrp':
                child_configs.append(
                    dict(eigrpExtP=dict(attributes=dict(descr='', nameAlias='', asn=asn))))
            elif protocol == 'ospf':
                child_configs.append(
                    dict(ospfExtP=dict(attributes=dict(descr='', nameAlias=''))))
            elif protocol == 'pim':
                child_configs.append(
                    dict(pimExtP=dict(attributes=dict(descr='', nameAlias=''))))

    if state == 'present':
        aci.payload(
            aci_class='l3extOut',
            class_config=dict(
                name=l3out,
                descr=description,
                dn='uni/tn-{0}/out-{1}'.format(tenant, l3out),
                enforceRtctrl=enforce_ctrl,
                targetDscp=dscp,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class='l3extOut')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
