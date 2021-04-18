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
        contract=dict(type='str', aliases=['contract_name', 'name']),  # Not required for querying all objects
        tenant=dict(type='str', aliases=['tenant_name']),  # Not required for querying all objects
        description=dict(type='str', aliases=['descr']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
        destination_tenant=dict(type='str'),
        name=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['name','destination_tenant','contract', 'tenant']],
            ['state', 'present', ['name','destination_tenant','contract', 'tenant']],
        ],
    )

    contract = module.params.get('contract')
    description = module.params.get('description')
    state = module.params.get('state')
    tenant = module.params.get('tenant')
    destination_tenant = module.params.get('destination_tenant')
    name = module.params.get('name')

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(destination_tenant),
            module_object=tenant,
            target_filter={'name': destination_tenant},
        ),
        subclass_1=dict(
            aci_class='vzCPIf',
            aci_rn='cif-{0}'.format(contract),
            module_object=contract,
            target_filter={'name': name},
        ),
    )

    aci.get_existing()

    if state == 'present':
        child_configs =[
            dict(
                vzRsIf=dict(
                    attributes=dict(
                        tDn='uni/tn-{0}/brc-{1}'.format(tenant,contract)
                    )
                )
            )
        ]
        aci.payload(
            aci_class='vzCPIf',
            class_config=dict(
                name=name,
                descr=description,
            ),
            child_configs=child_configs
        )

        aci.get_diff(aci_class='vzCPIf')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
