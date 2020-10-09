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
        logical_node=dict(type='str'), # Not required for querying all objects
        fabric_node=dict(type ='str'),
        static_route=dict(type='str', aliases=['address', 'ip']),
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
            ['state', 'present', ['static_route']],
            ['state', 'absent', ['static_route']],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get('tenant')
    l3out = module.params.get('l3out')
    logical_node = module.params.get('logical_node')
    fabric_node = module.params.get('fabric_node')
    static_route = module.params.get('static_route')
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
            aci_class='l3extRsNodeL3OutAtt',
            aci_rn='/rsnodeL3OutAtt-[{0}]'.format(fabric_node),
            module_object=fabric_node,
            target_filter={'name': fabric_node},
        ),
        subclass_4=dict(
            aci_class='ipRouteP',
            aci_rn='rt-[{0}]'.format(static_route),
            module_object=static_route,
            target_filter={'name': static_route},
        ),
    )

    aci.get_existing()

    aci.exit_json()


if __name__ == "__main__":
    main()
