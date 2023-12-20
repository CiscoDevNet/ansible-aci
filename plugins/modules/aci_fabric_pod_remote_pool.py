#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Samita Bhattacharjee (@samitab) <samitab@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_pod_remote_pool
short_description: Manage Fabric Pod Remote Pool (fabric:ExtSetupP)
description:
- Manage Remote Pools on Fabric Pod Subnets.
options:
  podId:
    description:
    - The Pod ID for the Remote Pool.
    type: int
    aliases: [ pod ]
  description:
    description:
    - The description for the Remote Pool
    type: str
    aliases: [desc]
  remoteId:
    description:
    - Remote Pool Identifier
    type: int
    aliases: [ id ]
  nameAlias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
  remotePool:
    description:
    - The subnet IP address pool
    type: str
    aliases: [ pool ]
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
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fabric:ExtSetupP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Samita Bhattacharjee (@samitab)
"""

EXAMPLES = r"""
- name: Add a Remote Pool to a pod fabic setup policy
  cisco.aci.aci_fabric_pod_remote_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    podId: 2
    id: 1
    pool: 10.6.2.0/24
    state: present
  delegate_to: localhost

- name: Delete a Remote Pool from a pod fabic setup policy
  cisco.aci.aci_fabric_pod_external_tep:
    host: apic
    username: admin
    password: SomeSecretPassword
    podId: 2
    remoteId: 1
    state: absent
  delegate_to: localhost

- name: Query the Remote Pool on a pod fabic setup policy
  cisco.aci.aci_fabric_pod_remote_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    podId: 2
    id: 1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query Remote Pools on all pod fabic setup policies
  cisco.aci.aci_fabric_pod_remote_pool:
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
        podId=dict(type=int, aliases=["pod"]),
        description=dict(type=str, aliases=["desc"]),
        remoteId=dict(type=int, aliases=["id"]),
        nameAlias=dict(type=str),
        remotePool=dict(type=str, aliases=["pool"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["podId", "remoteId"]],
            ["state", "present", ["podId", "remoteId"]],
        ],
    )

    aci = ACIModule(module)

    podId = module.params.get("podId")
    description = module.params.get("description")
    remoteId = module.params.get("remoteId")
    nameAlias = module.params.get("nameAlias")
    remotePool = module.params.get("remotePool")
    state = module.params.get("state")

    if podId is not None and int(podId) not in range(1, 254):
        aci.fail_json(msg="Pod ID: {0} is invalid; it must be in the range of 1 to 254.".format(podId))

    aci.construct_url(
        root_class=dict(
            aci_class="fabricSetupP",
            aci_rn="controller/setuppol/setupp-{0}".format(podId),
            module_object=podId,
            target_filter={"podId": podId},
        ),
        subclass_1=dict(aci_class="fabricExtSetupP", aci_rn="extsetupp-{0}".format(remoteId), module_object=remoteId, target_filter={"extPoolId": remoteId}),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fabricExtSetupP",
            class_config=dict(
                descr=description,
                extPoolId=remoteId,
                nameAlias=nameAlias,
                tepPool=remotePool,
            ),
        )

        aci.get_diff(aci_class="fabricExtSetupP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
