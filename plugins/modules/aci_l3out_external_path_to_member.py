#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        tenant=dict(type='str', aliases=['tenant_name']),  # Not required for querying all objects
        l3out=dict(type='str', aliases=['l3out_name']),  # Not required for querying all objects
        logical_node=dict(type='str'),  # Not required for querying all objects
        logical_interface=dict(type ='str'),
        leaf_port=dict(type='str'),
        member_node=dict(type ='str', aliases=['address', 'ip']),
        description=dict(type='str', aliases=['descr']),
        subnet_name=dict(type='str', aliases=['name']),
        scope=dict(type='list', elements='str', choices=['export-rtctrl', 'import-security', 'shared-rtctrl', 'shared-security']),
        state=dict(type='str', default='query'),
        name_alias=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'present', ['member_node']],
            ['state', 'absent', ['member_node']],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get('tenant')
    l3out = module.params.get('l3out')
    logical_node = module.params.get('logical_node')
    logical_interface = module.params.get('logical_interface')
    leaf_port = module.params.get('leaf_port')
    member_node = module.params.get('member_node')
    # description = module.params.get('description')
    # subnet_name = module.params.get('subnet_name')
    # scope = ','.join(sorted(module.params.get('scope')))
    # state = module.params.get('query')
    # name_alias = module.params.get('name_alias')

    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant},
        ),
        subclass_1=dict(
            aci_class='l3extOut',
            aci_rn='out-{0}'.format(l3out),
            module_object=l3out,
            target_filter={'name': l3out},
        ),
        subclass_2=dict(
            aci_class='l3extLNodeP',
            aci_rn='lnodep-{0}'.format(logical_node),
            module_object=logical_node,
            target_filter={'name': logical_node},
        ),
        subclass_3=dict(
            aci_class='l3extLIfP',
            aci_rn='/lifp-{0}'.format(logical_interface),
            module_object=logical_interface,
            target_filter={'name': logical_interface},
        ),
        subclass_4=dict(
            aci_class='l3extRsPathL3OutAtt',
            aci_rn='rspathL3OutAtt-[{0}]'.format(leaf_port),
            module_object=leaf_port,
            target_filter={'name': leaf_port},
        ),
        subclass_5=dict(
            aci_class='l3extMember',
            aci_rn='rt-[{0}]'.format(member_node),
            module_object=member_node,
            target_filter={'name': member_node},
        ),
    )

    aci.get_existing()

    aci.exit_json()


if __name__ == "__main__":
    main()
