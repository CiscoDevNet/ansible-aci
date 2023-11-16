#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Dag Wieers (@dagwieers)
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
    aliases: [action_rule_name, name ]
  set_community:
    description:
    - The set action rule based on communities.
    - To delete this attribute, pass an empty dictionary.
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
    - To delete this attribute, pass an empty dictionary.
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
    - To delete this attribute, pass an empty string.
    type: str
  next_hop_propagation:
    description:
    - The set action rule based on nexthop unchanged configuration.
    - Can not be configured along with C(set_route_tag).
    - Can not be configured for APIC version 4.2 and prior.
    - The APIC defaults to C(false) when unset.
    type: bool
  multipath:
    description:
    - Set action rule based on set redistribute multipath configuration.
    - Can not be configured along with C(set_route_tag).
    - Can not be configured for APIC version 4.2 and prior.
    - The APIC defaults to C(false) when unset.
    type: bool
  set_preference:
    description:
    - The set action rule based on preference.
    - To delete this attribute, pass an empty string.
    type: str
  set_metric:
    description:
    - The set action rule based on metric.
    - To delete this attribute, pass an empty string.
    type: str
  set_metric_type:
    description:
    - The set action rule based on a metric type.
    - To delete this attribute, pass an empty string.
    type: str
    choices: [ ospf_type_1, ospf_type_2, "" ]
  set_route_tag:
    description:
    - The set action rule based on route tag.
    - Can not be configured along with C(next_hop_propagation) and C(multipath).
    - To delete this attribute, pass an empty string.
    type: str
  set_weight:
    description:
    - The set action rule based on weight.
    - To delete this attribute, pass an empty string.
    type: str
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
    set_preference: 100
    set_weight: 100
    set_metric: 100
    set_metric_type: ospf_type_1
    set_next_hop: 1.1.1.1
    next_hop_propagation: true
    multipath: true
    set_community:
      community: no-advertise
      criteria: replace
    set_dampening:
      half_life: 10
      reuse: 1
      suppress: 10
      max_suppress_time: 100
    state: present
  delegate_to: localhost

- name: Delete action rule profile's children
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: prod
    set_preference: ""
    set_weight: ""
    set_metric: ""
    set_metric_type: ""
    set_next_hop: ""
    next_hop_propagation: false
    multipath: false
    set_community: {}
    set_dampening: {}
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    aci_annotation_spec,
    action_rule_set_comm_spec,
    action_rule_set_dampening_spec,
)
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
    description = module.params.get("description")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)

    # This dict contains the name of the child classes as well as the corresping attribute input (and attribute name if the input is a string)
    # this dict is deviating from normal child classes list structure in order to determine which child classes should be created, modified, deleted or ignored.
    child_classes = dict(
        rtctrlSetComm=dict(attribute_input=module.params.get("set_community")),
        rtctrlSetDamp=dict(attribute_input=module.params.get("set_dampening")),
        rtctrlSetNh=dict(attribute_input=module.params.get("set_next_hop"), attribute_name="addr"),
        rtctrlSetPref=dict(attribute_input=module.params.get("set_preference"), attribute_name="localPref"),
        rtctrlSetRtMetric=dict(attribute_input=module.params.get("set_metric"), attribute_name="metric"),
        rtctrlSetRtMetricType=dict(
            attribute_input=MATCH_ACTION_RULE_SET_METRIC_TYPE_MAPPING.get(module.params.get("set_metric_type")), attribute_name="metricType"
        ),
        rtctrlSetTag=dict(attribute_input=module.params.get("set_route_tag"), attribute_name="tag"),
        rtctrlSetWeight=dict(attribute_input=module.params.get("set_weight"), attribute_name="weight"),
    )

    # This condition deal with child classes which do not exist in APIC version 4.2 and prior.
    additional_child_classes = dict(
        rtctrlSetNhUnchanged=dict(attribute_input=module.params.get("next_hop_propagation")),
        rtctrlSetRedistMultipath=dict(attribute_input=module.params.get("multipath")),
    )
    for class_name, attribute in additional_child_classes.items():
        if attribute.get("attribute_input") is not None:
            child_classes[class_name] = attribute

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
        for class_name, attribute in child_classes.items():
            attribute_input = attribute.get("attribute_input")
            # This condition enables to user to keep its previous configurations if they are not passing anything in the payload.
            if attribute_input is not None:
                # This condition checks if the attribute input is a dict and checks if all of its values are None (stored as a boolean in only_none).
                only_none = False
                if isinstance(attribute_input, dict):
                    only_none = all(value is None for value in attribute_input.values())
                # This condition checks if the child object needs to be deleted depending on the type of the corresponding attribute input (bool, str, dict).
                if (attribute_input == "" or attribute_input is False or only_none) and isinstance(aci.existing, list) and len(aci.existing) > 0:
                    for child in aci.existing[0].get("rtctrlAttrP", {}).get("children", {}):
                        if child.get(class_name):
                            child_configs.append(
                                {
                                    class_name: dict(
                                        attributes=dict(status="deleted"),
                                    ),
                                }
                            )
                # This condition checks if the child object needs to be modified or created depending on the type of the corresponding attribute input.
                elif attribute_input != "" or attribute_input is True or attribute_input != {}:
                    if class_name == "rtctrlSetComm" and isinstance(attribute_input, dict):
                        child_configs.append(
                            {
                                class_name: dict(
                                    attributes=dict(
                                        community=attribute_input.get("community"),
                                        setCriteria=attribute_input.get("criteria"),
                                    ),
                                )
                            }
                        )
                    elif class_name == "rtctrlSetDamp" and isinstance(attribute_input, dict):
                        child_configs.append(
                            {
                                class_name: dict(
                                    attributes=dict(
                                        halfLife=attribute_input.get("half_life"),
                                        maxSuppressTime=attribute_input.get("max_suppress_time"),
                                        reuse=attribute_input.get("reuse"),
                                        suppress=attribute_input.get("suppress"),
                                    ),
                                )
                            }
                        )
                    elif class_name in ["rtctrlSetNhUnchanged", "rtctrlSetRedistMultipath"]:
                        child_configs.append({class_name: dict(attributes=dict(descr=""))})
                    else:
                        child_configs.append({class_name: dict(attributes={attribute.get("attribute_name"): attribute_input})})

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
