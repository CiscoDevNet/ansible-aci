#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_ip_sla_monitoring_policy
short_description: Manage IP SLA Monitoring Policies (fv:IPSLAMonitoringPol)
description:
- Manage IP SLA Monitoring Policies used for L4-L7 Policy Based Redirection
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  name:
    description:
    - The SLA Policy name.
    type: str
    aliases: [ sla_policy ]
  sla_type:
    description:
    - The type of monitoring.
    type: str
    choices: [ icmp, tcp, l2ping, http ]
  sla_port:
    description:
    - The Port to monitor for TCP SLAs.
    type: int
  frequency:
    description:
    - How often to probe.
    type: int
  multiplier:
    description:
    - How many probes must fail for the SLA to be down.
    type: int
  request_data_size:
    description:
    - The number of bytes to send in the request.
    - Only used if C(sla_type) is C(http)
    type: int
  type_of_service:
    description:
    - The Type of Service (ToS) value to set in the IPv4 header.
    type: str
    aliases: [ tos ]
  operation_timeout:
    description:
    - The amount of time in milliseconds that the IP SLA operation waits for a response from its request packet.
    type: int
  threshold:
    description:
    - The upper threshold value in milliseconds for calculating network monitoring statistics created by the IP SLA operation.
    - The value specified for this property must not exceed the value specified for operation_timeout.
    type: int
  traffic_class:
    description:
    - The Traffic Class value to set in the IPv6 header.
    type: int
  http_version:
    description:
    - The HTTP version to use.
    type: str
    choices: [ 1.0, 1.1 ]
  http_uri:
    description:
    - The HTTP URI to use as the SLA destination.
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
- cisco.aci.aci_annotation
- cisco.aci.aci_owner

notes:
- The C(tenant) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) modules can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fvIPSLAMonitoringPol)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new ICMP SLA monitoring policy
  cisco.aci.aci_ip_sla_monitoring_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    name: my_policy
    sla_type: icmp
    frequency: 40
    multiplier: 6
    state: present
  delegate_to: localhost

- name: Add a new TCP SLA monitoring policy
  cisco.aci.aci_ip_sla_monitoring_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    name: my_policy
    sla_type: tcp
    sla_port: 2345
    frequency: 45
    multiplier: 5
    state: present
  delegate_to: localhost

- name: Delete an SLA monitoring policy
  cisco.aci.aci_ip_sla_monitoring_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    name: my_policy
    state: absent
  delegate_to: localhost

- name: Query an SLA monitoring policy
  cisco.aci.aci_ip_sla_monitoring_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    name: my_policy
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all SLA monitoring policies
  cisco.aci.aci_ip_sla_monitoring_policy:
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name=dict(type="str", aliases=["sla_policy"]),
        sla_type=dict(type="str", choices=["icmp", "tcp", "l2ping", "http"]),
        sla_port=dict(type="int"),
        frequency=dict(type="int"),
        multiplier=dict(type="int"),
        request_data_size=dict(type="int"),
        type_of_service=dict(type="int", aliases=["tos"]),
        operation_timeout=dict(type="int"),
        threshold=dict(type="int"),
        traffic_class=dict(type="int"),
        http_version=dict(type="str", choices=["1.0", "1.1"]),
        http_uri=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True, required_if=[["state", "absent", ["tenant", "name"]], ["state", "present", ["tenant", "name"]]]
    )

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    name = module.params.get("name")
    sla_type = module.params.get("sla_type")
    sla_port = module.params.get("sla_port")
    frequency = module.params.get("frequency")
    multiplier = module.params.get("multiplier")
    request_data_size = module.params.get("request_data_size")
    type_of_service = module.params.get("type_of_service")
    operation_timeout = module.params.get("operation_timeout")
    threshold = module.params.get("threshold")
    traffic_class = module.params.get("traffic_class")
    http_version = module.params.get("http_version")
    http_uri = module.params.get("http_uri")

    aci = ACIModule(module)

    if sla_port is not None:
        if sla_type != "tcp":
            aci.fail_json("sla_port is only used if sla_type is tcp")

    if http_version == "1.0":
        parsed_http = "HTTP10"
    elif http_version == "1.1":
        parsed_http = "HTTP11"
    else:
        parsed_http = None

    if sla_type == "http":
        sla_port = 80

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(aci_class="fvIPSLAMonitoringPol", aci_rn="ipslaMonitoringPol-{0}".format(name), module_object=name, target_filter={"name": name}),
    )
    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fvIPSLAMonitoringPol",
            class_config=dict(
                name=name,
                slaType=sla_type,
                slaPort=sla_port,
                slaFrequency=frequency,
                slaDetectMultiplier=multiplier,
                reqDataSize=request_data_size,
                ipv4Tos=type_of_service,
                timeout=operation_timeout,
                threshold=threshold,
                ipv6TrfClass=traffic_class,
                httpVersion=parsed_http,
                httpUri=http_uri,
            ),
        )
        aci.get_diff(aci_class="fvIPSLAMonitoringPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
