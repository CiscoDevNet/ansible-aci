#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_interface_policy_eigrp
short_description: Manage EIGRP interface policies (eigrp:IfPol)
description:
- Manage EIGRP interface policies on Cisco ACI fabrics.
options:

  tenant:
    description:
    - The name of the Tenant the EIGRP interface policy should belong to.
    type: str
    aliases: [ tenant_name ]

  eigrp:
    description:
    - The EIGRP interface policy name.
    - This name can be between 1 and 64 alphanumeric characters.
    - Note that you cannot change this name after the object has been saved.
    type: str
    aliases: [ eigrp_interface, name ]

  description:
    description:
    - The description for the EIGRP interface.
    - This name can be between 0 and 128 alphanumeric characters.
    type: str
    aliases: [ descr ]

  controls:
    description:
    - The interface policy controls.
    - 'This is a list of one or more of the following controls:'
    - C(bfd) -- Bidirectional Forwarding Detection
    - C(nh-self) -- Nexthop Self.
    - C(split-horizon) -- Split Horizon.
    - C(passive) -- The interface does not participate in the EIGRP protocol and
      will not establish adjacencies or send routing updates.
    - The APIC defaults to C(split-horizon,nh-self) when unset during creation.
    type: list
    elements: str
    choices: [ split-horizon, bfd, nh-self, passive ]

  hello_interval:
    description:
    - The time interval in seconds between hello packets that EIGRP sends on the interface.
    - Note that the smaller the hello interval, the faster topological changes will be detected, but more routing traffic will ensue.
    - Accepted values range between C(1) and C(65535).
    - The APIC defaults to C(5) when unset during creation.
    type: int

  hold_interval:
    description:
    - The time period of time in seconds before declaring that the neighbor is down.
    - Accepted values range between C(1) and C(65535).
    - The APIC defaults to C(15) when unset during creation.
    type: int

  bw:
    description:
    - The administrative port bandwidth.
    - Accepted values range between C(0) and C(2560000000).
    - The APIC defaults to C(0) when unset during creation.
    type: int

  delay:
    description:
    - The administrative port delay.
    - Accepted values ranges between C(0) and C(inf).
    - The APIC defaults to C(0) when unset during creation.
    type: int

  delayUnit:
    description:
    - EIGRP delay units.
    - Wide metrics can use picosecond accuracy for delay.
    - 'This is a list of possible options:'
    - C(pico) -- Picoseconds
    - C(tens-of-micro) -- Tens of microseconds.
    - The APIC defaults to C(tens-of-micro) when unset during creation.
    type: str
    choices: [ pico, tens-of-micro ]

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
    - This name can be between 0 and 63 alphanumeric characters.
    type: str

extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(eigrp:IfPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Lukas Holub (@lukasholub)
"""

EXAMPLES = r"""
- name: Ensure eigrp interface policy exists
  cisco.aci.aci_interface_policy_eigrp:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    eigrp: eigrp1
    state: present
  delegate_to: localhost

- name: Ensure eigrp interface policy does not exist
  cisco.aci.aci_interface_policy_eigrp:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    eigrp: eigrp1
    state: absent
  delegate_to: localhost

- name: Query an eigrp interface policy
  cisco.aci.aci_interface_policy_eigrp:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    eigrp: eigrp1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all eigrp interface policies in tenant production
  cisco.aci.aci_interface_policy_eigrp:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
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
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        eigrp=dict(type="str", aliases=["eigrp_interface", "name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        bw=dict(type="int"),
        delay=dict(type="int"),
        controls=dict(type="list", elements="str", choices=["split-horizon", "bfd", "nh-self", "passive"]),
        hold_interval=dict(type="int", default="15"),
        hello_interval=dict(type="int", default="5"),
        delayUnit=dict(type="str", default="tens-of-micro"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["eigrp", "tenant"]],
            ["state", "present", ["eigrp", "tenant"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    eigrp = module.params.get("eigrp")
    description = module.params.get("description")
    name_alias = module.params.get("name_alias")

    if module.params.get("controls") is None:
        controls = None
    else:
        controls = ",".join(module.params.get("controls"))

    bw = module.params.get("bw")
    if bw is not None and bw not in range(0, 2560000000):
        module.fail_json(msg="Parameter 'bw' is only valid in range between 0 and 2560000000.")

    hold_interval = module.params.get("hold_interval")
    if hold_interval is not None and hold_interval not in range(1, 65536):
        module.fail_json(msg="Parameter 'dead_interval' is only valid in range between 1 and 65536.")

    hello_interval = module.params.get("hello_interval")
    if hello_interval is not None and hello_interval not in range(1, 65536):
        module.fail_json(msg="Parameter 'hello_interval' is only valid in range between 1 and 65536.")

    delay = module.params.get("delay")
    if delay is not None and delay < 0:
        module.fail_json(msg="Parameter 'delay' is only valid if 'delay' > 0.")

    delayUnit = module.params.get("delayUnit")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="eigrpIfPol",
            aci_rn="tn-{0}/eigrpIfPol-{1}".format(tenant, eigrp),
            module_object=eigrp,
            target_filter={"name": eigrp},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="eigrpIfPol",
            class_config=dict(
                name=eigrp,
                descr=description,
                bw=bw,
                ctrl=controls,
                holdIntvl=hold_interval,
                helloIntvl=hello_interval,
                delay=delay,
                delayUnit=delayUnit,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="eigrpIfPol")
        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
