#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Samita Bhattacharjee (@samitab) <samitab@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from ansible_collections.cisco.aci.plugins.module_utils import constants

__metaclass__ = type

ANSIBLE_METADATA = constants.ANSIBLE_METADATA

DOCUMENTATION = r"""
---
module: aci_fabric_pod_profile
short_description: Manage Fabric Pod Profile (fabric:PodP)
description:
- Manage Fabric Pod Profile on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the Pod Profile.
    type: str
    aliases: [ profile, pod_profile ]
  description:
    description:
    - The description for the Fabric Pod Profile.
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
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fabric:PodP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Samita Bhattacharjee (@samitab)
"""

EXAMPLES = r"""
- name: Add a new pod profile
  cisco.aci.aci_fabric_pod_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_pod_profile
    state: present
  delegate_to: localhost

- name: Remove a pod profile
  cisco.aci.aci_fabric_pod_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_pod_profile
    state: absent
  delegate_to: localhost

- name: Query a pod profile
  cisco.aci.aci_fabric_pod_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_pod_profile
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all pod profiles
  cisco.aci.aci_fabric_pod_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result
"""

RETURN = constants.RETURN_DOC

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    aci_annotation_spec,
    aci_owner_spec,
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
        name=dict(type="str", aliases=["profile", "pod_profile"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
    )

    aci = ACIModule(module)

    name_alias = module.params.get("name_alias")
    name = module.params.get("name")
    description = module.params.get("description")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="fabricPodP",
            aci_rn="fabric/podprof-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=["fabricPodS"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fabricPodP",
            class_config=dict(
                name=name,
                descr=description,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="fabricPodP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
