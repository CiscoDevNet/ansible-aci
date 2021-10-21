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
module: aci_fabric_switch_association
short_description: Manage spine and leaf switch fabric bindings to profiles and policy groups.
description:
- Manage fabric spine/leaf switch (fabric:SpineS / fabric:LeafS) associations to an existing fabric
  spine/leaf profile (fabric:SpineP / fabric:LeafP) in an ACI fabric, and bind them to a
  policy group (fabric:RsSpNodePGrp / fabric:RsLeNodePGrp)
options:
  profile:
    description:
    - Name of an existing fabric switch profile
    type: str
    aliases: [ spine_profile, spine_switch_profile, leaf_profile, leaf_switch_profile ]
  name:
    description:
    - Name of the switch association
    type: str
    aliases: [ association_name, switch_association ]
  switch_type:
    description:
    - Type of switch profile, leaf or spine
    type: str
    choices: [ leaf, spine ]
    required: yes
  policy_group:
    description:
    - Name of an existing switch policy group
    type: str
  description:
    description:
    - Description of the Fabric Switch Association
    type: str
    aliases: [ descr ]
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
- The C(profile) must exist before using this module in your playbook.
  The M(cisco.aci.aci_fabric_switch_profile) module can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(fabricSpineS), B(fabricLeafS), B(fabricRsSpNodePGrp) and B(fabricRsLeNodePGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
'''

EXAMPLES = r'''
- name: Create spine fabric switch profile association
  cisco.aci.aci_fabric_switch_association:
    host: apic
    username: admin
    password: SomeSecretPassword
    profile: my_spine_profile
    switch_type: spine
    name: my_spine_switch_assoc
    policy_group: my_spine_pol_grp
    state: present
  delegate_to: localhost

- name: Remove spine fabric switch profile association
  cisco.aci.aci_fabric_switch_association:
    host: apic
    username: admin
    password: SomeSecretPassword
    profile: my_spine_profile
    switch_type: spine
    name: my_spine_switch_assoc
    state: absent
  delegate_to: localhost

- name: Query spine fabric switch profile association
  cisco.aci.aci_fabric_switch_association:
    host: apic
    username: admin
    password: SomeSecretPassword
    profile: my_spine_profile
    name: my_spine_switch_assoc
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all leaf fabric switch profiles
  cisco.aci.aci_fabric_switch_assocication:
    host: apic
    username: admin
    password: SomeSecretPassword
    switch_type: leaf
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


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        profile=dict(type='str', aliases=['spine_profile',
                                          'spine_switch_profile',
                                          'leaf_profile',
                                          'leaf_switch_profile']),
        switch_type=dict(type='str', choices=['leaf', 'spine'], required=True),
        name=dict(type='str', aliases=['association_name',
                                       'switch_association']),
        policy_group=dict(type='str'),
        description=dict(type='str', aliases=['descr']),
        state=dict(type='str', default='present',
                   choices=['absent', 'present', 'query'])
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['profile', 'name']],
            ['state', 'present', ['profile', 'name']],
        ]
    )

    aci = ACIModule(module)

    profile = module.params.get('profile')
    switch_type = module.params.get('switch_type')
    name = module.params.get('name')
    policy_group = module.params.get('policy_group')
    description = module.params.get('description')
    state = module.params.get('state')

    child_classes = ['fabricNodeBlk']
    child_configs = list()

    if switch_type == 'spine':
        aci_root_class = 'fabricSpineP'
        aci_root_rn = 'fabric/spprof-{0}'.format(profile)
        aci_subclass_class = 'fabricSpineS'
        aci_subclass_rn = 'spines-{0}-typ-range'.format(name)
        child_classes.append('fabricRsSpNodePGrp')
        if policy_group is not None:
            child_configs.append(
                dict(fabricRsSpNodePGrp=dict(attributes=dict(tDn='uni/fabric/funcprof/spnodepgrp-{0}'.format(policy_group))))
            )
    elif switch_type == 'leaf':
        aci_root_class = 'fabricLeafP'
        aci_root_rn = 'fabric/leprof-{0}'.format(profile)
        aci_subclass_class = 'fabricLeafS'
        aci_subclass_rn = 'leaves-{0}-typ-range'.format(name)
        child_classes.append('fabricRsLeNodePGrp')
        if policy_group is not None:
            child_configs.append(
                dict(fabricRsLeNodePGrp=dict(attributes=dict(tDn='uni/fabric/funcprof/lenodepgrp-{0}'.format(policy_group))))
            )

    aci.construct_url(
        root_class=dict(
            aci_class=aci_root_class,
            aci_rn=aci_root_rn,
            module_object=profile,
            target_filter={'name': profile},
        ),
        subclass_1=dict(
            aci_class=aci_subclass_class,
            aci_rn=aci_subclass_rn,
            module_object=name,
            target_filter={'name': name},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == 'present':
        aci.payload(
            aci_class=aci_subclass_class,
            class_config=dict(
                name=name,
                descr=description
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class=aci_subclass_class)

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
