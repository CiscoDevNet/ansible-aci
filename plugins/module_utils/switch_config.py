# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Samita Bhattacharjee (@samiib)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    aci_annotation_spec,
)

POLICY_GROUP_DN_FORMAT_MAP = {
    "fabricNodeConfig": {
        "spine": "uni/fabric/funcprof/spnodepgrp-{0}",
        "leaf": "uni/fabric/funcprof/lenodepgrp-{0}",
    },
    "infraNodeConfig": {
        "spine": "uni/infra/funcprof/spaccnodepgrp-{0}",
        "leaf": "uni/infra/funcprof/accnodepgrp-{0}",
    },
}


class SwitchConfig(object):
    def __init__(self, moClass):
        self.moClass = moClass

    def main(self):
        policy_type = "fabric" if self.moClass == "fabricNodeConfig" else "access"
        rn_format = "fabric/nodeconfnode-{0}" if self.moClass == "fabricNodeConfig" else "infra/nodeconfnode-{0}"

        argument_spec = aci_argument_spec()
        argument_spec.update(aci_annotation_spec())
        argument_spec.update(
            node_type=dict(type="str", aliases=["type", "switch_type"], choices=["leaf", "spine"]),
            node=dict(type="int", aliases=["node_id"]),
            policy_group=dict(
                type="str",
                aliases=[
                    "{0}_policy".format(policy_type),
                    "{0}_policy_group".format(policy_type),
                ],
            ),
            state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        )

        module = AnsibleModule(
            argument_spec=argument_spec,
            supports_check_mode=True,
            required_if=[
                ["state", "absent", ["node"]],
                ["state", "present", ["node", "node_type", "policy_group"]],
            ],
        )

        node = module.params.get("node")
        node_type = module.params.get("node_type")
        policy_group = module.params.get("policy_group")
        state = module.params.get("state")

        aci = ACIModule(module)
        aci.construct_url(
            root_class=dict(
                aci_class=self.moClass,
                target_filter=dict(node=node),
                aci_rn=rn_format.format(node),
            ),
        )

        aci.get_existing()

        if state == "present":
            config = dict(node=node)
            if policy_group is not None:
                config["assocGrp"] = POLICY_GROUP_DN_FORMAT_MAP[self.moClass][node_type].format(policy_group)
            aci.payload(
                aci_class=self.moClass,
                class_config=config,
            )

            aci.get_diff(aci_class=self.moClass)

            aci.post_config()

        elif state == "absent":
            aci.delete_config()

        aci.exit_json()
