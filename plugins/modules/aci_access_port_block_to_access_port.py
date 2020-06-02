#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Simon Metzger <smnmtzgr@gmail.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
---
module: aci_access_port_block_to_access_port
short_description: Manage port blocks of Fabric interface policy leaf profile interface selectors (infra:HPortS, infra:PortBlk)
description:
- Manage port blocks of Fabric interface policy leaf profile interface selectors on Cisco ACI fabrics.
options:
  interface_profile:
    description:
    - The name of the Fabric access policy leaf interface profile.
    type: str
    required: yes
    aliases: [ interface_profile_name ]
  access_port_selector:
    description:
    -  The name of the Fabric access policy leaf interface profile access port selector.
    type: str
    required: yes
    aliases: [ name, access_port_selector_name ]
  fex_port:
    description:
    - Determines if the port resides on a fex
    type: bool
    default: no
  port_blk:
    description:
    - The name of the Fabric access policy leaf interface profile access port block.
    type: str
    required: yes
    aliases: [ port_blk_name ]
  port_blk_description:
    description:
    - The description to assign to the C(port_blk).
    type: str
  from_port:
    description:
    - The beginning (from-range) of the port range block for the leaf access port block.
    type: str
    required: yes
    aliases: [ from, fromPort, from_port_range ]
  to_port:
    description:
    - The end (to-range) of the port range block for the leaf access port block.
    type: str
    required: yes
    aliases: [ to, toPort, to_port_range ]
  from_card:
    description:
    - The beginning (from-range) of the card range block for the leaf access port block.
    type: str
    aliases: [ from_card_range ]
  to_card:
    description:
    - The end (to-range) of the card range block for the leaf access port block.
    type: str
    aliases: [ to_card_range ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(infra:HPortS) and B(infra:PortBlk).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Simon Metzger (@smnmtzgr)
'''

EXAMPLES = r'''
- name: Associate an access port block (single port) to an interface selector
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    interface_profile: intprfname
    access_port_selector: accessportselectorname
    port_blk: portblkname
    from_port: 13
    to_port: 13
    state: present
  delegate_to: localhost

- name: Associate an access port block (single port) to an interface selector on a fex
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    interface_profile: intprfname
    access_port_selector: accessportselectorname
    fex_port: yes
    port_blk: portblkname
    from_port: 13
    to_port: 13
    state: present
  delegate_to: localhost

- name: Associate an access port block (port range) to an interface selector
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    interface_profile: intprfname
    access_port_selector: accessportselectorname
    port_blk: portblkname
    from_port: 13
    to_port: 16
    state: present
  delegate_to: localhost

- name: Remove an access port block from an interface selector
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    interface_profile: intprfname
    access_port_selector: accessportselectorname
    port_blk: portblkname
    from_port: 13
    to_port: 13
    state: absent
  delegate_to: localhost

- name: Query Specific access port block under given access port selector
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    interface_profile: intprfname
    access_port_selector: accessportselectorname
    port_blk: portblkname
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all access port blocks under given leaf interface profile
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    interface_profile: intprfname
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all access port blocks in the fabric
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result
'''

RETURN = r'''
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
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        interface_profile=dict(type='str', aliases=['interface_profile_name']),  # Not required for querying all objects
        access_port_selector=dict(type='str', aliases=['name', 'access_port_selector_name']),  # Not required for querying all objects
        fex_port=dict(type=bool, default=False),   # This parameter is not required for querying all objects
        port_blk=dict(type='str', aliases=['port_blk_name']),  # Not required for querying all objects
        port_blk_description=dict(type='str'),
        from_port=dict(type='str', aliases=['from', 'fromPort', 'from_port_range']),
        to_port=dict(type='str', aliases=['to', 'toPort', 'to_port_range']),
        from_card=dict(type='str', aliases=['from_card_range']),
        to_card=dict(type='str', aliases=['to_card_range']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['access_port_selector', 'port_blk', 'interface_profile']],
            ['state', 'present', ['access_port_selector', 'port_blk', 'from_port', 'to_port', 'interface_profile']],
        ],
    )

    interface_profile = module.params.get('interface_profile')
    access_port_selector = module.params.get('access_port_selector')
    fex_port = module.params.get('fex_port')
    port_blk = module.params.get('port_blk')
    port_blk_description = module.params.get('port_blk_description')
    from_port = module.params.get('from_port')
    to_port = module.params.get('to_port')
    from_card = module.params.get('from_card')
    to_card = module.params.get('to_card')
    state = module.params.get('state')

    aci = ACIModule(module)
    if fex_port is True:
      aci.construct_url(
        root_class=dict(
            aci_class='infraFexP',
            aci_rn='infra/fexprof-{0}'.format(interface_profile),
            module_object=interface_profile,
            target_filter={'name': interface_profile},
        ),
        subclass_1=dict(
            aci_class='infraHPortS',
            # NOTE: normal rn: hports-{name}-typ-{type}, hence here hardcoded to range for purposes of module
            aci_rn='hports-{0}-typ-range'.format(access_port_selector),
            module_object=access_port_selector,
            target_filter={'name': access_port_selector},
        ),
        subclass_2=dict(
            aci_class='infraPortBlk',
            aci_rn='portblk-{0}'.format(port_blk),
            module_object=port_blk,
            target_filter={'name': port_blk},
        ),
    )
    else:
      aci.construct_url(
        root_class=dict(
            aci_class='infraAccPortP',
            aci_rn='infra/accportprof-{0}'.format(interface_profile),
            module_object=interface_profile,
            target_filter={'name': interface_profile},
        ),
        subclass_1=dict(
            aci_class='infraHPortS',
            # NOTE: normal rn: hports-{name}-typ-{type}, hence here hardcoded to range for purposes of module
            aci_rn='hports-{0}-typ-range'.format(access_port_selector),
            module_object=access_port_selector,
            target_filter={'name': access_port_selector},
        ),
        subclass_2=dict(
            aci_class='infraPortBlk',
            aci_rn='portblk-{0}'.format(port_blk),
            module_object=port_blk,
            target_filter={'name': port_blk},
        ),
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='infraPortBlk',
            class_config=dict(
                descr=port_blk_description,
                name=port_blk,
                fromPort=from_port,
                toPort=to_port,
                fromCard=from_card,
                toCard=to_card,
                #  type='range',
            ),
        )

        aci.get_diff(aci_class='infraPortBlk')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
