#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_pod_selector
short_description: Manage Fabric Pod Selectors (fabric:PodS)
description:
- Manage Fabric Pod Selectors on Cisco ACI fabrics.
options:
  pod_profile:
    description:
    - The name of the Pod Profile that contains the Selector.
    type: str
  name:
    description:
    - The name of the Pod Selector.
    type: str
    aliases: [ selector, pod_selector ]
  description:
    description:
    - The description for the Fabric Pod Selector.
    type: str
    aliases: [ descr ]
  selector_type:
    description:
    - The type of the Pod Selector.
    type: str
    choices: [ ALL, range ]
  policy_group:
    description:
    - The Fabric Policy Group to bind to this Pod Selector.
    type: str
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fabric:PodS).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new pod selector
  cisco.aci.aci_fabric_pod_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_profile: default
    name: ans_pod_selector
    selector_type: ALL
    policy_group: ansible_policy_group
    state: present
  delegate_to: localhost

- name: Remove a pod selector
  cisco.aci.aci_fabric_pod_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_profile: default
    name: ans_pod_selector
    state: absent
  delegate_to: localhost

- name: Query a pod selector
  cisco.aci.aci_fabric_pod_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_profile: default
    name: ans_pod_selector
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all pod selectors
  cisco.aci.aci_fabric_pod_selector:
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
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
        pod_profile=dict(type="str"),
        name=dict(type="str", aliases=["selector", "pod_selector"]),
        selector_type=dict(type="str", choices=["ALL", "range"]),
        policy_group=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["pod_profile", "name", "selector_type"]],
            ["state", "present", ["pod_profile", "name", "selector_type"]],
        ],
    )

    aci = ACIModule(module)

    name_alias = module.params.get("name_alias")
    pod_profile = module.params.get("pod_profile")
    name = module.params.get("name")
    selector_type = module.params.get("selector_type")
    policy_group = module.params.get("policy_group")
    description = module.params.get("description")
    state = module.params.get("state")

    child_classes = ["fabricRsPodPGrp"]

    aci.construct_url(
        root_class=dict(
            aci_class="fabricPodP",
            aci_rn="fabric/podprof-{0}".format(pod_profile),
            module_object=pod_profile,
            target_filter={"name": pod_profile},
        ),
        subclass_1=dict(
            aci_class="fabricPodS",
            aci_rn="pods-{0}-typ-{1}".format(name, selector_type),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if policy_group is not None:
            tDn = "uni/fabric/funcprof/podpgrp-{0}".format(policy_group)
            child_configs.append({"fabricRsPodPGrp": {"attributes": {"tDn": tDn}}})

        aci.payload(
            aci_class="fabricPodS",
            class_config=dict(
                name=name,
                descr=description,
                nameAlias=name_alias,
                type=selector_type,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="fabricPodS")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
