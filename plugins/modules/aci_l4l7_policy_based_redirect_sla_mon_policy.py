#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l4l7_policy_based_redirect_sla_mon_policy
short_description: Manage L4-L7 Policy Based Redirect SLA Monitor Policies (vns:RsIPSLAMonitoringPol)
description:
- Bind an existing IP SLA Monitoring Policy to an L4-L7 Policy Based Redirect Destination
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  pbr_name:
    description:
    - Name of an existing Policy Based Redirect Policy
    type: str
    aliases: [ policy, policy_based_redirect ]
  monitor_policy:
    description:
    - Name of the IP SLA Monitoring Policy
    type: str
    aliases: [ sla, sla_policy ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci

notes:
- The C(tenant), C(pbr_name) and C(monitor_policy) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_l4l7_policy_based_redirect)
  and M(cisco.aci.aci_ip_sla_monitoring_policy) modules can be used for this.
seealso:
- module: aci_l4l7_policy_based_redirect
- module: aci_ip_sla_monitoring_policy
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vnsRsIPSLAMonitoringPol)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Bind an IP SLA monitoring policy to a Policy Based Redirect Policy
  cisco.aci.aci_l4l7_policy_based_redirect_sla_mon_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    pbr_name: my_pbr_policy
    monitor_policy: my_ip_sla_mon
    state: present
  delegate_to: localhost

- name: Remove an IP SLA monitoring policy from a Policy Based Redirect Policy
  cisco.aci.aci_l4l7_policy_based_redirect_sla_mon_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    pbr_name: my_pbr_policy
    monitor_policy: my_ip_sla_mon
    state: absent
  delegate_to: localhost

- name: Query what IP SLA monitor is bound to a PBR Policy
  cisco.aci.aci_l4l7_policy_based_redirect_sla_mon_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    pbr_name: my_pbr_policy
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all SLA monitor bindings
  cisco.aci.aci_l4l7_policy_based_redirect_sla_mon_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        pbr_name=dict(type="str", aliases=["policy", "policy_based_redirect"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        monitor_policy=dict(type="str", aliases=["sla", "sla_policy"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[["state", "absent", ["tenant", "pbr_name", "monitor_policy"]], ["state", "present", ["tenant", "pbr_name", "monitor_policy"]]],
    )

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    pbr_name = module.params.get("pbr_name")
    monitor_policy = module.params.get("monitor_policy")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="svcRedirectPol",
            aci_rn="svcCont/svcRedirectPol-{0}".format(pbr_name),
            module_object=pbr_name,
            target_filter={"name": pbr_name},
        ),
        subclass_2=dict(
            aci_class="vnsRsIPSLAMonitoringPol",
            aci_rn="rsIPSLAMonitoringPol",
            module_object=monitor_policy,
            target_filter={"tDn": "uni/tn-{0}/ipslaMonitoringPol-{1}".format(tenant, monitor_policy)},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="vnsRsIPSLAMonitoringPol",
            class_config=dict(tDn="uni/tn-{0}/ipslaMonitoringPol-{1}".format(tenant, monitor_policy)),
        )
        aci.get_diff(aci_class="vnsRsIPSLAMonitoringPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
