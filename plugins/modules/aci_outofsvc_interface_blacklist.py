#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
---
module: aci_outofsvc_interface_blacklist
short_description: Enabling or Disabling physical interfaces.
description:
- Manages enabling and disabling physical interfaces on Cisco ACI fabrics.
options:
  pod_id:
    description:
    - ID of the pod eq. 1
    type: int
  node_id:
    description:
    - ID of the node eq. 105
    type: int
  interface:
    description:
    - Name of the interface eq. eth1/49 | FEX eq. eth123/1/33
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

author:
- Akini Ross (@akinross)
'''

EXAMPLES = r'''
- name: Disable Interface
  cisco.aci.aci_outofsvc_interface_blacklist:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: no
    pod_id: 1
    node_id: 105
    interface: eth1/49
    state: present
  delegate_to: localhost

- name: Enable Interface
  cisco.aci.aci_outofsvc_interface_blacklist:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: no
    pod_id: 1
    node_id: 105
    interface: eth1/49
    state: absent
  delegate_to: localhost

- name: Query Interface
  cisco.aci.aci_outofsvc_interface_blacklist:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: no
    pod_id: 1
    node_id: 105
    interface: eth1/49
    state: query
  delegate_to: localhost
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
  sample: '?rsp-prop-include=config-only'
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
        pod_id=dict(type='int', required=True),
        node_id=dict(type='int', required=True),
        interface=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    aci = ACIModule(module)

    pod_id = module.params.get('pod_id')
    node_id = module.params.get('node_id')
    interface = module.params.get('interface')
    state = module.params.get('state')

    # Set rn based on node type determined by looking at interface input
    if len(interface.split("/")) > 2:
        fex_id = interface.split("/")[0].lstrip("eth")
        fex_int = "eth{}".format('/'.join(interface.split("/")[1:3]))
        rn = 'fabric/outofsvc/rsoosPath-[topology/pod-{0}/paths-{1}/extpaths-{2}/pathep-[{3}]]'.format(pod_id,
                                                                                                       node_id,
                                                                                                       fex_id,
                                                                                                       fex_int)
    else:
        rn = 'fabric/outofsvc/rsoosPath-[topology/pod-{0}/paths-{1}/pathep-[{2}]]'.format(pod_id, node_id, interface)

    aci.construct_url(
        root_class=dict(
            aci_class='fabricRsOosPath',
            aci_rn=rn
        )
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class='fabricRsOosPath',
            class_config=dict(
                lc="blacklist",
            ),
        )

        aci.get_diff(aci_class='fabricRsOosPath')

        aci.post_config()

    elif state == 'absent':

        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
