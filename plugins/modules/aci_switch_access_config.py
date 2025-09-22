#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Samita Bhattacharjee (@samiib)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: aci_switch_access_config
version_added: "2.13.0"
short_description: Manage Switch Access Policy Configuration of Leaf and Spine nodes (infra:NodeConfig).
description:
- Manage Switch Access Policy Configuration of Leaf and Spine nodes (infra:NodeConfig) on Cisco ACI fabrics.
options:
  node_type:
    description:
    - The type of Node.
    type: str
    aliases: [ type, switch_type ]
    choices: [ leaf, spine ]
  node:
    description:
    - The ID of the Node.
    - The value must be between 101 to 4000.
    type: int
    aliases: [ node_id ]
  policy_group:
    description:
    - The name of the Leaf/Spine Access Policy Group to associate with the node.
    type: str
    aliases: [ access_policy_group, access_policy ]
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

seealso:
- module: cisco.aci.aci_access_switch_policy_group
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(infra:NodeConfig).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Samita Bhattacharjee (@samiib)
"""

EXAMPLES = r"""
- name: Add Switch Access Policy Configuration to a Leaf node
  cisco.aci.aci_switch_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    node: 101
    node_type: leaf
    policy_group: ansible_leaf_access_policy
    state: present
  delegate_to: localhost

- name: Query Switch Access Policy Configuration for a specific node
  cisco.aci.aci_switch_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    node: 101
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Switch Access Policy Configurations
  cisco.aci.aci_switch_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove a Switch Access Policy Configuration
  cisco.aci.aci_switch_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    node: 101
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
     sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class "/></imdata>'
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

from ansible_collections.cisco.aci.plugins.module_utils.switch_config import SwitchConfig


def main():
    SwitchConfig("infraNodeConfig").main()


if __name__ == "__main__":
    main()
