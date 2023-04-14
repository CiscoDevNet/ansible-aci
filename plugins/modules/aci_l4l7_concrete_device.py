#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l4l7_concrete_device
short_description: Manage L4-L7 Concrete Devices (vns:CDev)
description:
- Manage L4-L7 Concrete Devices.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  device:
    description:
    - The name of the logical device (vns:lDevVip) the concrete device is attached to.
    - The logical device can be configured using the M(cisco.aci.aci_l4l7_device) module.
    type: str
    aliases: [ device_name, logical_device_name ]
  name:
    description:
    - The name of the concrete device.
    type: str
    aliases: [ concrete_device, concrete_device_name ]
  vcenter_name:
    description:
    - The virtual center name on which the device is hosted in the L4-L7 device cluster.
    type: str
  vm_name:
    description:
    - The virtual center VM name on which the device is hosted in the L4-L7 device cluster.
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
- The C(tenant) and C(device) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_l4l7_device) modules can be used for this.
seealso:
- module: aci_l4l7_device
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(vns:CDev)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new concrete device
  cisco.aci.aci_l4l7_concrete_device:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    concrete_device: my_concrete_device
    state: present
  delegate_to: localhost

- name: Delete a concrete device
  cisco.aci.aci_l4l7_concrete_device:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    concrete_device: my_concrete_device
    state: absent
  delegate_to: localhost

- name: Query a concrete device
  cisco.aci.aci_l4l7_concrete_device:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    concrete_device: my_concrete_device
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all concrete devices
  cisco.aci.aci_l4l7_concrete_device:
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
        device=dict(type="str", aliases=["device_name", "logical_device_name"]),
        name=dict(type="str", aliases=["concrete_device", "concrete_device_name"]),
        vcenter_name=dict(type="str"),
        vm_name=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[["state", "absent", ["tenant", "device", "concrete_device"]], ["state", "present", ["tenant", "device", "concrete_device"]]],
    )

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    device = module.params.get("device")
    name = module.params.get("name")
    vcenter_name = module.params.get("vcenter_name")
    vm_name = module.params.get("vm_name")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="vnsLDevVip",
            aci_rn="lDevVip-{0}".format(device),
            module_object=device,
            target_filter={"name": device},
        ),
        subclass_2=dict(
            aci_class="vnsCDev",
            aci_rn="cDev-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="vnsCDev",
            class_config=dict(
                name=name,
                vcenterName=vcenter_name,
                vmName=vm_name,
            ),
        )
        aci.get_diff(aci_class="vnsCDev")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
