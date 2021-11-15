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
- Tagging objects on Cisco ACI fabrics.
options:
  dn:
    description:
    - Unique Distinguished Name (DN) from ACI object model.
    type: str
  tag_annotation:
    description:
    - A simple note or description.
    type: dict
  tag_inst:
    description:
    - A simple note or description.
    type: list
    aliases: [ epg_name, name ]
  tag:
    description: 
    - A label for grouping of objects, which need not be of the same class.
    type: dict
    aliases: [ policy_tag ]
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
  description: More information about the tagging.
  link: https://www.cisco.com/c/en/us/td/docs/dcn/aci/apic/5x/system-management-configuration/cisco-apic-system-management-configuration-guide-52x/m-alias-annotations-and-tags.html
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
    tag_annotation:
      someKey: someValue
      foo: bar
    tag_inst:
      - blah
    tag:
      bar: foo
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
        dn=dict(type='str'),
        tag_annotation=dict(type='dict', default={}),
        tag_inst=dict(type='list', default=[]),
        tag=dict(type='dict', default={}, aliases=['policy_tag']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['dn']],
            ['state', 'present', ['dn']],
        ],
        required_one_of=[
            ('annotation', 'tag_inst', 'tag'),
        ],
    )

    # add validate step for dn?
    dn = module.params.get('dn')

    tag_annotation = module.params.get('tag_annotation')
    tag_inst = module.params.get('tag_inst')
    tag = module.params.get('tag')
    state = module.params.get('state')

    child_configs = [dict(tagAnnotation=dict(attributes=dict(key=k, value=v))) for k, v in tag_annotation.items()]
    child_configs.extend([dict(tagInst=dict(attributes=dict(name=n))) for n in tag_inst])
    child_configs.extend([dict(tagTag=dict(attributes=dict(key=k, value=v))) for k, v in tag.items()])

    aci = ACIModule(module)
    # sets aci.child_classes
    # aci.py row 676
    # if child_classes is None:
    #     self.child_classes = set()
    # else:
    #     self.child_classes = set(child_classes)
    aci.child_classes = {'tagAnnotation', 'tagInst', 'tagTag'}
    # aci.py row 696
    # if self.child_classes:
    #     # Append child_classes to filter_string if filter string is empty
    #     self.update_qs({'rsp-subtree': 'full', 'rsp-subtree-class': ','.join(sorted(self.child_classes))})
    aci.update_qs({'rsp-subtree': 'full', 'rsp-subtree-class': ','.join(sorted(aci.child_classes))})
    # sets aci.path in _construct_url_1 (n depth)
    # aci.py row 711
    # self.path = 'api/mo/uni/{0}.json'.format(obj_rn)
    aci.path = 'api/mo/{0}.json'.format(dn)
    # sets aci.url
    # aci.py row 691
    if aci.params.get('port') is not None:
        aci.url = '{protocol}://{host}:{port}/{path}'.format(path=aci.path, **aci.module.params)
    else:
        aci.url = '{protocol}://{host}/{path}'.format(path=aci.path, **aci.module.params)

    # no class available so pbb should set vars in comments above in advance to get_existing()
    # aci.construct_url(
    #     root_class=dict(
    #         aci_class='fvTenant',
    #         aci_rn='tn-{0}',
    #         module_object="tenant",
    #         target_filter={'name': "tenant"},
    #     ),
    #     child_classes=['tagAnnotation', 'tagInst', 'tagTag'],
    # )

    # when vars in above comments set, think this should still work
    aci.get_existing()

    if state == 'present':
        # payload should represent the children of object only as defined in child_configs
        # if no class from dn url multiple tags will need to be multiple rest calls...
        # writes to self.existing = json.loads(resp.read())['imdata']
        # retrieves class from self.existing ( check length is 1 ? )
        # next(iter(self.existing[0]))
        # class config should not be needed and child_configs should suffice?
        class_name = next(iter(aci.existing[0]))
        aci.payload(
            aci_class=class_name,
            class_config={},
            child_configs=child_configs,
        )

        # use retrieved class
        aci.get_diff(aci_class=class_name)

        # when vars in above comments set, think this should still work
        # tagInst also creates a tagAnnotation object, should also be deleted
        aci.post_config()

    elif state == 'absent':

        # for each tag new dn should be calculated to delete, url will point to the object and remove it instead of tag
        # ex dn = uni/tn-{name}/ap-{name}/epg-{name}/
        # ex dn for delete = uni/tn-{name}/ap-{name}/epg-{name}/tagKey-{key}
        del_base_url = aci.url.rstrip(".json")
        for child in child_configs:
            for class_name, values in child.items():
                if class_name == "tagAnnotation":
                    aci.url = '{0}/annotationKey-{1}.json'.format(del_base_url, values['attributes']['key'])
                elif class_name == "tagTag":
                    aci.url = '{0}/tagKey-{1}.json'.format(del_base_url, values['attributes']['key'])
                elif class_name == "tagInst":
                    # Add logic to delete the tagAnnotation object aligned with the tagInst created object.
                    aci.url = '{0}/tag-{1}.json'.format(del_base_url, values['attributes']['name'])
                else:
                    # should never be the case
                    continue
                aci.delete_config()

    # When state absent and when having multiple tag deletes the printed output is incorrect
    # Will only show last child since the values are overwritten by delete_config in this current way of delete
    aci.exit_json()


if __name__ == "__main__":
    main()
