#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Tim Cragg (@timcragg) <tcragg@cisco.com>
# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_tenant_action_rule_profile
short_description: Manage action rule profiles (rtctrl:AttrP)
description:
- Manage action rule profiles on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of the tenant.
    type: str
    aliases: [ tenant_name ]
  action_rule:
    description:
    - The name of the action rule profile.
    type: str
    aliases: [ action_rule_name, name ]
  set_community:
    description:
    - The set action rule based on communities.
    type: dict
    suboptions:
      community:
        description:
        - The community value.
        type: str
      criteria:
        description:
        - The community criteria.
        - The option to append or replace the community value.
        type: str
        choices: [ append, replace, none ]
  set_dampening:
    description:
    - The set action rule based on dampening.
    type: dict
    suboptions:
      half_life:
        description:
        - The half life value (minutes).
        type: int
      max_suppress_time:
        description:
        - The maximum suppress time value (minutes).
        type: int
      reuse:
        description:
        - The reuse limit value.
        type: int
      suppress:
        description:
        - The suppress limit value.
        type: int
  set_next_hop:
    description:
    - The set action rule based on the next hop address.
    type: str
  next_hop_propagation:
    description:
    - The set action rule based on nexthop unchanged configuration.
    - Can not be configured along with C(set_route_tag).
    - The APIC defaults to C(false) when unset.
    type: bool
  multipath:
    description:
    - Set action rule based on set redistribute multipath configuration.
    - Can not be configured along with C(set_route_tag).
    - The APIC defaults to C(false) when unset.
    type: bool
  set_preference:
    description:
    - The set action rule based on preference.
    type: int
  set_metric:
    description:
    - The set action rule based on metric.
    type: int
  set_metric_type:
    description:
    - The set action rule based on a metric type.
    type: str
    choices: [ ospf_type_1, ospf_type_2 ]
  set_route_tag:
    description:
    - The set action rule based on route tag.
    - Can not be configured along with C(next_hop_propagation) and C(multipath).
    type: int
  set_weight:
    description:
    - The set action rule based on weight.
    type: int
  description:
    description:
    - The description for the action rule profile.
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
- cisco.aci.annotation

notes:
- The C(tenant) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(rtctrl:AttrP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Dag Wieers (@dagwieers)
- Tim Cragg (@timcragg)
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Create a action rule profile
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: prod
    state: present
  delegate_to: localhost

- name: Delete a action rule profile
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: prod
    state: absent
  delegate_to: localhost

- name: Query all action rule profiles
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific action rule profile
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: prod
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, action_rule_set_comm_spec, action_rule_set_dampening_spec, check_all_none_values_dict 
from ansible_collections.cisco.aci.plugins.module_utils.constants import MATCH_ACTION_RULE_SET_METRIC_TYPE_MAPPING

def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        action_rule=dict(type="str", aliases=["action_rule_name", "name"]),  # Not required for querying all objects
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        set_community=dict(type="dict", options=action_rule_set_comm_spec()),
        set_dampening=dict(type="dict", options=action_rule_set_dampening_spec()),
        set_next_hop=dict(type="str"),
        next_hop_propagation=dict(type="bool"),
        multipath=dict(type="bool"),
        set_preference=dict(type="str"),
        set_metric=dict(type="str"),
        set_metric_type=dict(type="str", choices=["ospf_type_1", "ospf_type_2", ""]),
        set_route_tag=dict(type="str"),
        set_weight=dict(type="str"),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["action_rule", "tenant"]],
            ["state", "present", ["action_rule", "tenant"]],
        ],
    )

    action_rule = module.params.get("action_rule")
    set_community = module.params.get("set_community")
    set_dampening = module.params.get("set_dampening")
    set_next_hop = module.params.get("set_next_hop")
    next_hop_propagation = module.params.get("next_hop_propagation")
    multipath = module.params.get("multipath")
    set_preference = module.params.get("set_preference")
    set_metric = module.params.get("set_metric")
    set_metric_type = MATCH_ACTION_RULE_SET_METRIC_TYPE_MAPPING.get(module.params.get("set_metric_type"))
    set_route_tag = module.params.get("set_route_tag")
    set_weight = module.params.get("set_weight")
    description = module.params.get("description")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)

    child_classes = dict(
        rtctrlSetComm=[set_community],
        rtctrlSetDamp=[set_dampening],
        rtctrlSetNh=[set_next_hop, "addr"],
        rtctrlSetNhUnchanged=[next_hop_propagation],
        rtctrlSetPref=[set_preference, "localPref"],
        rtctrlSetRedistMultipath=[multipath],
        rtctrlSetRtMetric=[set_metric, "metric"],
        rtctrlSetRtMetricType=[set_metric_type, "metricType"],
        rtctrlSetTag=[set_route_tag, "tag"],
        rtctrlSetWeight=[set_weight, "weight"],
    )
    
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="rtctrlAttrP",
            aci_rn="attr-{0}".format(action_rule),
            module_object=action_rule,
            target_filter={"name": action_rule},
        ),
        child_classes=list(child_classes.keys()),
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        for key, value in child_classes.items():
            if value[0] is not None:
                if value[0] == "" or value[0] == False or check_all_none_values_dict(value[0]):
                    if isinstance(aci.existing, list) and len(aci.existing) > 0:
                        for child in aci.existing[0].get("rtctrlAttrP", {}).get("children", {}):
                            if child.get(key):
                                child_configs.append(
                                    {
                                        key:dict(
                                            attributes=dict(status="deleted"),
                                        ),
                                    }
                                )
                elif value[0] != "" or value[0] == True or value[0] != {}:
                    if key == "rtctrlSetComm" and isinstance(value[0], dict):
                        child_configs.append(
                            {
                                key:dict(
                                    attributes=dict(
                                        community=value[0].get("community"),
                                        setCriteria=value[0].get("criteria"),
                                    ),
                                )
                            }
                        )
                    elif key == "rtctrlSetDamp" and isinstance(value[0], dict):
                        child_configs.append(
                            {
                                key:dict(
                                    attributes=dict(
                                        halfLife=value[0].get("half_life"),
                                        maxSuppressTime=value[0].get("max_suppress_time"),
                                        reuse=value[0].get("reuse"),
                                        suppress=value[0].get("suppress"),
                                    ),
                                )
                            }
                        )
                    elif key in ["rtctrlSetNhUnchanged", "rtctrlSetRedistMultipath"]:
                        child_configs.append({key:dict(attributes=dict(descr=""))})
                    else:
                        child_configs.append({key:dict(attributes={value[-1]:value[0]})})

        aci.payload(
            aci_class="rtctrlAttrP",
            class_config=dict(
                name=action_rule,
                descr=description,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="rtctrlAttrP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
