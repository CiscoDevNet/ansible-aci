#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Sabari Jaganathan <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_infra_port_config
short_description: Manage the Port Configuration of the Fabric Access Policies - Interface Configuration (infra:PortConfig)
description:
- Manage the Port Configuration of the Fabric Access Policies - Interface Configuration on Cisco ACI fabrics.
options:
  assoc_grp:
    description:
    - The Associated Group DN of the Access Port Policy Group.
    type: str
    aliases: [ access_port_policy_group ]
  brkout_map:
    description:
    - The Breakout Map of the interface and assoc_grp should be empty while configuring the Breakout Map.
    type: str
    choices: [ 100g-4x, 10g-4x, 25g-4x ]
    aliases: [ breakout_map ]
  card:
    description:
    - The slot number of the Network Interface Card(NIC) and the Card ID must be between 1 to 64.
    type: int
  description:
    description:
    - Description of the Interface Port Configuration object.
    type: str
    aliases: [ descr ]
  node:
    description:
    - The ID of the Node and the value must be between 101 to 4000.
    type: int
    aliases: [ node_id ]
  pc_member:
    description:
    - The name of the Port Channel Member.
    type: str
    aliases: [ port_channel_member ]
  port_type:
    description:
    - The type of the interface port can be either access or fabric and the default port type is access.
    type: str
    default: access
    choices: [ access, fabric ]
  port_id:
    description:
    - The Port ID of the Network Interface Card(NIC) and the Port ID must be between 1 to 128.
    type: int
    aliases: [ port_channel_member ]
  role:
    description:
    - The type of the interface can be either a leaf or a spine and the default Node type is leaf.
    type: str
    aliases: [ node_type ]
    choices: [ leaf, spine ]
  shutdown:
    description:
    - The Admin State of the Interface and the default Admin State is Up.
    - C(no) used to set the Admin State - Up and C(yes) used to set the Admin State - Down.
    type: str
    aliases: [ admin_state ]
    choices: [ "yes", "no" ]
  sub_port:
    description:
    - The Sub Port ID of the Network Interface Card(NIC) and the Sub Port ID must be between 1 to 16.
    type: int
    default: 0
    aliases: [ sub_port_id ]
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
  description: More information about the internal APIC class B(infra:PortConfig).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sabari Jaganathan (@sajagana)
"""

EXAMPLES = r"""
- name: Add the interface with port channel(PC) policy group
  cisco.aci.aci_infra_port_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    role: "leaf"
    assoc_grp: "{{ ansible_pc.current.0.infraAccBndlGrp.attributes.dn }}"
    node: 201
    card: 1
    port_id: 1
    sub_port: 0
    state: present
  delegate_to: localhost

- name: Breakout the existing interface with "100g-4x"
  cisco.aci.aci_infra_port_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    role: "leaf"
    node: 201
    card: 1
    port_id: 1
    sub_port: 0
    brkout_map: "100g-4x"
    state: present
  delegate_to: localhost

- name: Query a access interface with node id
  cisco.aci.aci_infra_port_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    node: 201
    state: query
  delegate_to: localhost

- name: Query a fabric interface with node id
  cisco.aci.aci_infra_port_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    node: 201
    port_type: fabric
    state: query
  delegate_to: localhost

- name: Query all access interfaces
  cisco.aci.aci_infra_port_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Query all fabric interfaces
  cisco.aci.aci_infra_port_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    port_type: fabric
    state: query
  delegate_to: localhost

- name: Remove a interface
  cisco.aci.aci_infra_port_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    node: 201
    card: 1
    port_id: 1
    sub_port: 0
    state: absent
  delegate_to: localhost
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
        assoc_grp=dict(type="str", aliases=["access_port_policy_group"]),
        brkout_map=dict(type="str", aliases=["breakout_map"], choices=["100g-4x", "10g-4x", "25g-4x"]),
        card=dict(type="int"),
        description=dict(type="str", aliases=["descr"]),
        node=dict(type="int", aliases=["node_id"]),
        pc_member=dict(type="str", aliases=["port_channel_member"]),
        port_type=dict(type="str", default="access", choices=["access", "fabric"]),
        port_id=dict(type="int"),
        role=dict(type="str", choices=["leaf", "spine"], aliases=["node_type"]),
        shutdown=dict(type="str", choices=["yes", "no"], aliases=["admin_state"]),
        sub_port=dict(type="int", default=0, aliases=["sub_port_id"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["node", "card", "port_type", "port_id", "sub_port"]],
            ["state", "present", ["node", "card", "port_type", "port_id", "sub_port"]],
            ["state", "query", ["port_type"]],
        ],
        mutually_exclusive=[("assoc_grp", "brkout_map")],
    )

    assoc_grp = module.params.get("assoc_grp")
    brkout_map = module.params.get("brkout_map")
    card = module.params.get("card")
    description = module.params.get("description")
    node = module.params.get("node")
    pc_member = module.params.get("pc_member")
    port_type = module.params.get("port_type")
    port_id = module.params.get("port_id")
    role = module.params.get("role")
    shutdown = module.params.get("shutdown")
    sub_port = module.params.get("sub_port")
    state = module.params.get("state")

    aci = ACIModule(module)

    error_message = []

    if node is not None and node not in range(101, 4001):
        error_message.append("Node ID must be between 101 to 4000")

    if card is not None and card not in range(1, 65):
        error_message.append("Card ID must be between 1 to 64")

    if port_id is not None and port_id not in range(1, 129):
        error_message.append("Port ID must be between 1 to 128")

    # Sub Port ID - 0 is default value
    if sub_port is not None and sub_port not in range(0, 17):
        error_message.append("Sub Port ID must be between 1 to 16")

    if error_message:
        aci.fail_json(msg="Interface Configuration failed due to: {0}".format(error_message))

    interface_class_name = "infraPortConfig" if port_type == "access" else "fabricPortConfig"
    root_class_name = "infraInfra" if port_type == "access" else "fabricInst"
    root_class_rn = "infra" if port_type == "access" else "fabric"

    aci.construct_url(
        root_class=dict(
            aci_class=root_class_name,
            aci_rn=root_class_rn,
        ),
        subclass_1=dict(
            aci_class=interface_class_name,
            aci_rn="portconfnode-{0}-card-{1}-port-{2}-sub-{3}".format(node, card, port_id, sub_port),
            target_filter=dict(node=node),
        ),
    )

    aci.get_existing()

    # To handle the existing object property
    if brkout_map:
        assoc_grp = ""

    if state == "present":
        aci.payload(
            aci_class=interface_class_name,
            class_config=dict(
                assocGrp=assoc_grp,
                brkoutMap=brkout_map,
                card=card,
                description=description,
                node=node,
                pcMember=pc_member,
                port=port_id,
                role=role,
                shutdown=shutdown,
                subPort=sub_port,
            ),
        )

        aci.get_diff(aci_class=interface_class_name)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
