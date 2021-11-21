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
module: aci_tag
short_description: Tagging of ACI objects
description:
- Tagging a object on Cisco ACI fabric.
options:
  dn:
    description:
    - Unique Distinguished Name (DN) from ACI object model.
    type: str
  key:
    description:
    - Unique identifier of tag object.
    type: str
  value:
    description:
    - Value of the property.
    type: str
  tag_type:
    description:
    - Type of tag object.
    type: str
    choices: [ annotation, instance, tag ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci

notes:
- The ACI object must exist before using this module in your playbook.
seealso:
- name: Cisco APIC System Management Configuration Guide
  description: More information about the tagging can be found in the Cisco APIC System Management Configuration Guide.
  link: https://www.cisco.com/c/en/us/support/cloud-systems-management/application-policy-infrastructure-controller-apic/tsd-products-support-series-home.html
author:
- Akini Ross (@akinross)
'''

EXAMPLES = r'''
- name: Add a new annotation tag
  cisco.aci.aci_tag:
    host: apic
    username: admin
    password: SomeSecretPassword
    dn: SomeValidAciDN
    key: foo
    value: bar
    tag_type: annotation
    state: present
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
        dn=dict(type='str', required=True),
        tag_key=dict(type='str'),
        tag_value=dict(type='str'),
        tag_type=dict(type='str', choices=['annotation', 'instance', 'tag']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['tag_key', 'tag_type']],
            ['state', 'present', ['tag_key', 'tag_type']],
            ['tag_type', 'annotation', ['tag_value']],
            ['tag_type', 'tag', ['tag_value']],
        ],
    )

    aci = ACIModule(module)

    dn = module.params.get('dn')
    tag_key = module.params.get('tag_key')
    tag_value = module.params.get('tag_value')
    tag_type = module.params.get('tag_type')
    state = module.params.get('state')

    aci.path = ""
    class_name = ""
    class_config = ""
    if tag_type == 'annotation':
        aci.path = 'api/mo/{0}/annotationKey-{1}.json'.format(dn, tag_key)
        class_config = dict(value=tag_value)
        class_name = "tagAnnotation"
    elif tag_type == 'instance':
        aci.path = 'api/mo/{0}/tag-{1}.json'.format(dn, tag_key)
        class_config = dict()
        class_name = "tagInst"
    elif tag_type == 'tag':
        aci.path = 'api/mo/{0}/tagKey-{1}.json'.format(dn, tag_key)
        class_config = dict(value=tag_value)
        class_name = "tagTag"

    if aci.params.get('port') is not None:
        aci.url = '{protocol}://{host}:{port}/{path}'.format(path=aci.path, **aci.module.params)
    else:
        aci.url = '{protocol}://{host}/{path}'.format(path=aci.path, **aci.module.params)

    aci.get_existing()

    if state == 'present':

        aci.payload(
            aci_class=class_name,
            class_config=class_config
        )
        aci.get_diff(aci_class=class_name)
        aci.post_config()

    elif state == 'absent':

        # TODO Add logic to delete the tagAnnotation object aligned with the tagInst created object?
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
