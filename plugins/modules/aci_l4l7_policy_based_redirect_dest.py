#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l4l7_policy_based_redirect_dest
short_description: Manage L4-L7 Policy Based Redirect Destinations (vns:RedirectDest and vns:L1L2RedirectDest)
description:
- Manage L4-L7 Policy Based Redirect Destinations
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  policy:
    description:
    - The name of an existing Policy Based Redirect Policy.
    type: str
    aliases: [ policy_name ]
  ip:
    description:
    - The destination IP for redirection.
    - Only used if I(dest_type=l3)
    aliases: [ redirect_ip ]
    type: str
  additional_ip:
    description:
    - The Additional IP Address for the Destination.
    - Only used if I(dest_type=l3)
    type: str
  logical_dev:
    description:
    - The destination Logical Device for redirection.
    - Only used if I(dest_type=l1/l2)
    type: str
  concrete_dev:
    description:
    - The destination Concrete Device for redirection.
    - Only used if I(dest_type=l1/l2)
    type: str
  concrete_intf:
    description:
    - The destination Concrete Interface for redirection.
    - Only used if I(dest_type=l1/l2)
    type: str
  mac:
    description:
    - The destination MAC address for redirection.
    type: str
    aliases: [ redirect_mac ]
  dest_name:
    description:
    - The name for Policy Based Redirect destination.
    type: str
  dest_type:
    description:
    - The destination type.
    type: str
    choices: [ l1/l2, l3 ]
    default: l3
  pod_id:
    description:
    - The Pod ID to deploy Policy Based Redirect destination on.
    - The APIC defaults to C(1) when unset during creation.
    type: int
  health_group:
    description:
    - The Health Group to bind the Policy Based Redirection Destination to.
    - To remove an existing binding from a Health Group, submit a request with I(state=present) and no I(health_group) value.
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
- cisco.aci.annotation

notes:
- The I(tenant) and I(policy) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_l4l7_policy_based_redirect) modules can be used for this.
seealso:
- module: aci_l4l7_policy_based_redirect
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vns:RedirectDest)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add destination to a Policy Based Redirect Policy
  cisco.aci.aci_l4l7_policy_based_redirect_dest:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy: my_pbr_policy
    dest_type: l3
    ip: 192.168.10.1
    mac: AB:CD:EF:12:34:56
    dest_name: redirect_dest
    pod_id: 1
    state: present
  delegate_to: localhost

- name: Remove destination from a Policy Based Redirect Policy
  cisco.aci.aci_l4l7_policy_based_redirect_dest:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy: my_pbr_policy
    state: absent
  delegate_to: localhost

- name: Query destinations for a Policy Based Redirect Policy
  cisco.aci.aci_l4l7_policy_based_redirect_dest:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    policy: my_pbr_policy
    state: query
  delegate_to: localhost
  register: query_result

- name: Query destinations for all Policy Based Redirect Policies
  cisco.aci.aci_l4l7_policy_based_redirect_dest:
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        policy=dict(type="str", aliases=["policy_name"]),
        ip=dict(type="str", aliases=["redirect_ip"]),
        additional_ip=dict(type="str"),
        mac=dict(type="str", aliases=["redirect_mac"]),
        logical_dev=dict(type="str"),
        concrete_dev=dict(type="str"),
        concrete_intf=dict(type="str"),
        dest_name=dict(type="str"),
        dest_type=dict(type="str", default="l3", choices=["l1/l2", "l3"]),
        health_group=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        pod_id=dict(type="int"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[["state", "absent", ["tenant", "policy"]], ["state", "present", ["tenant", "policy"]]],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    policy = module.params.get("policy")
    ip = module.params.get("ip")
    additional_ip = module.params.get("additional_ip")
    mac = module.params.get("mac")
    logical_dev = module.params.get("logical_dev")
    concrete_dev = module.params.get("concrete_dev")
    concrete_intf = module.params.get("concrete_intf")
    dest_name = module.params.get("dest_name")
    dest_type = module.params.get("dest_type")
    health_group = module.params.get("health_group")
    state = module.params.get("state")
    pod_id = module.params.get("pod_id")

    if dest_type == "l3":
        aci_class = "vnsRedirectDest"
        aci_rn = "RedirectDest_ip-[{0}]".format(ip)
        module_object = ip
        target_filter = {"ip": ip}
        child_classes = ["vnsRsRedirectHealthGroup"]
        redirect_hg_class = "vnsRsRedirectHealthGroup"
    elif dest_type == "l1/l2":
        aci_class = "vnsL1L2RedirectDest"
        aci_rn = "L1L2RedirectDest-[{0}]".format(dest_name)
        module_object = dest_name
        target_filter = {"destName": dest_name}
        child_classes = ["vnsRsL1L2RedirectHealthGroup", "vnsRsToCIf"]
        redirect_hg_class = "vnsRsL1L2RedirectHealthGroup"

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="vnsSvcRedirectPol",
            aci_rn="svcCont/svcRedirectPol-{0}".format(policy),
            module_object=policy,
            target_filter={"name": policy},
        ),
        subclass_2=dict(
            aci_class=aci_class,
            aci_rn=aci_rn,
            module_object=module_object,
            target_filter=target_filter,
        ),
        child_classes=child_classes,
    )
    aci.get_existing()

    if state == "present":
        if dest_type == "l1/l2" and additional_ip is not None:
            aci.fail_json(msg="You cannot provide an additional_ip when configuring an l1/l2 destination")
        elif dest_type == "l3" and (logical_dev, concrete_dev, concrete_intf) != (None, None, None):
            aci.fail_json(msg="You cannot provide a logical_dev, concrete_dev or concrete_intf when configuring an l3 destination")
        elif dest_type == "l1/l2" and (logical_dev, concrete_dev, concrete_intf) == (None, None, None):
            aci.fail_json(msg="You must provide a logical_dev, concrete_dev and concrete_intf when configuring an l1/l2 destination")
        elif dest_type == "l1/l2" and ip is not None:
            aci.fail_json(msg="You cannot provide an ip when configuring an l1/l2 destination")
        if dest_type == "l3":
            child_configs = []
        elif dest_type == "l1/l2":
            child_configs = [
                {"vnsRsToCIf": {"attributes": {"tDn": "uni/tn-{0}/lDevVip-{1}/cDev-{2}/cIf-[{3}]".format(tenant, logical_dev, concrete_dev, concrete_intf)}}}
            ]
        if health_group is not None:
            health_group_tdn = "uni/tn-{0}/svcCont/redirectHealthGroup-{1}".format(tenant, health_group)
            child_configs.append({redirect_hg_class: {"attributes": {"tDn": health_group_tdn}}})
        else:
            health_group_tdn = None
        if isinstance(aci.existing, list) and len(aci.existing) > 0:
            for child in aci.existing[0].get(aci_class, {}).get("children", {}):
                if child.get(redirect_hg_class) and child.get(redirect_hg_class).get("attributes").get("tDn") != health_group_tdn:
                    child_configs.append(
                        {
                            redirect_hg_class: {
                                "attributes": {
                                    "dn": child.get(redirect_hg_class).get("attributes").get("dn"),
                                    "status": "deleted",
                                }
                            }
                        }
                    )
        aci.payload(
            aci_class=aci_class,
            class_config=dict(ip=ip, mac=mac, destName=dest_name, podId=pod_id, ip2=additional_ip),
            child_configs=child_configs,
        )
        aci.get_diff(aci_class=aci_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
