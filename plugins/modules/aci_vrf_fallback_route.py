#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec

def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        vrf=dict(type="str", aliases=["context", "vrf_name"]),
        vrf_fallback_route_group=dict(type="str", aliases = ["name"]),
        fallback_route=dict(type="str", aliases = ["prefix_address"]),
        fallback_members=dict(type="list", aliases = ["next_hop_address"]),
        description=dict(type="str", aliases=["descr"]), 
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant"]],
            ["state", "present", ["tenant"]],
        ],
    )

    tenant=module.params.get("tenant")
    vrf=module.params.get("vrf")
    vrf_fallback_route_group=module.params.get("vrf_fallback_route_group")
    fallback_route=module.params.get("fallback_route")
    fallback_members=module.params.get("fallback_members")
    description=module.params.get("description")
    state=module.params.get("state")

    aci=ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="fvCtx",
            aci_rn="ctx-{0}".format(vrf),
            module_object=vrf,
            target_filter={"name": vrf},
        ),
        subclass_2=dict(
            aci_class="fvFBRGroup", #TODO Check if this is correct
            aci_rn="fbrg-{0}".format(vrf_fallback_route_group),
            module_object=vrf_fallback_route_group,
            target_filter={"name"},
        ),
        child_classes=["fvFBRMember", "fvFBRoute"],
    )

    aci.get_existing()

    if state == "present":

        child_configs=[]

        existing_members=[]
        existing_route=None
        
        if isinstance(aci.existing, list) and len(aci.existing) > 0:
            for child in aci.existing[0].get("fvFBRGroup",{}).get("children", {}):
                existing_member = child.get("fvFBRMember", {}).get("attributes",{}).get("rnhAddr")
                if existing_member:
                    existing_members.append(existing_member)
                existing_route = child.get("fvFBRoute", {}).get("attributes",{}).get("fbrPrefix")
    

        for member in fallback_members:
            if member not in existing_members:
                child_configs.append(
                        dict(
                            fvFBRMember=dict(attributes=dict(rnhAddr=member))
                        )
                    )
        
        for existing_member in existing_members:
             if existing_member not in fallback_members:
                  child_configs.append(
                       dict(
                            fvFBRMember=dict(attributes=dict(rnhAddr=member, status="deleted"))
                       )
                  )
      
        if fallback_route != existing_route:
            if existing_route:
                child_configs.append(
                    dict(
                        fvFBRoute=dict(
                            attributes=dict(
                                fbrPrefix=existing_route,
                                status="deleted",
                            )
                        )
                        )

                )
            child_configs.append(
                dict(
                    fvFBRoute=dict(
                        attributes=dict(
                            fbrPrefix=fallback_route
                        )
                    )
                    ),
            )


        aci.payload(
            aci_class="fvFBRGroup",
            class_config=dict(
                descr=description,
                name=vrf_fallback_route_group,
            ),
            child_configs=child_configs
        )

        aci.get_diff(aci_class="fvFBRGroup")

        aci.post_config()
    elif state == "absent":
        aci.delete_config()

    aci.exit_json()





if __name__ == "__main__":
    main()