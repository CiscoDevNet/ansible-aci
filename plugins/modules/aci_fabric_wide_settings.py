#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_wide_settings
short_description: Manage Fabric Wide Settings (infra:SetPol)
description:
- Manage Fabric Wide Settings on Cisco ACI fabrics.
options:
  disable_remote_ep_learning:
    description:
    - Disable remote endpoint learning in VRFs containing external bridged/routed domains.
    type: bool
  enforce_subnet_check:
    description:
    - Disable IP address learning on the outside of subnets configured in a VRF, for all VRFs.
    type: bool
  enforce_epg_vlan_validation:
    description:
    - Validation check that prevents overlapping VLAN pools from being associated to an EPG.
    type: bool
  enforce_domain_validation:
    description:
    - Validation check if a static path is added but no domain is associated to an EPG.
    - Asking for domain validation is a one time operation. Once enabled, it cannot be disabled.
    type: bool
  spine_opflex_client_auth:
    description:
    - Enforce Opflex client certificate authentication on spine switches for GOLF and Linux.
    type: bool
  leaf_opflex_client_auth:
    description:
    - Enforce Opflex client certificate authentication on leaf switches for GOLF and Linux.
    type: bool
  spine_ssl_opflex:
    description:
    - Enable SSL Opflex transport for spine switches.
    type: bool
  leaf_ssl_opflex:
    description:
    - Enable SSL Opflex transport for leaf switches.
    type: bool
  ssl_opflex_tls_10:
    description:
    - Enable Opflex TLS1.0.
    type: bool
  ssl_opflex_tls_11:
    description:
    - Enable Opflex TLS1.1.
    type: bool
  ssl_opflex_tls_12:
    description:
    - Enable Opflex TLS1.2.
    type: bool
  reallocate_gipo:
    description:
    - Reallocate some non-stretched BD gipos to make room for stretched BDs.
    - Asking for gipo reallocation is a one time operation. Once enabled, it cannot be disabled.
    type: bool
  restrict_infra_vlan_traffic:
    description:
    - Restrict infra VLAN traffic to only specified network paths. These enabled network paths are defined by infra security entry policies.
    type: bool
  state:
    description:
    - Use C(present) for updating configuration.
    - Use C(query) for showing current configuration.
    type: str
    choices: [ present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(infra:SetPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Update Fabric Wide Settings
  cisco.aci.aci_fabric_wide_settings:
    host: apic
    username: admin
    password: SomeSecretPassword
    disable_remote_ep_learning: true
    enforce_epg_vlan_validation: true
    state: present
  delegate_to: localhost

- name: Query Fabric Wide Settings
  cisco.aci.aci_fabric_wide_settings:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

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
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        disable_remote_ep_learning=dict(type="bool"),
        enforce_subnet_check=dict(type="bool"),
        enforce_epg_vlan_validation=dict(type="bool"),
        enforce_domain_validation=dict(type="bool"),
        spine_opflex_client_auth=dict(type="bool"),
        leaf_opflex_client_auth=dict(type="bool"),
        spine_ssl_opflex=dict(type="bool"),
        leaf_ssl_opflex=dict(type="bool"),
        ssl_opflex_tls_10=dict(type="bool"),
        ssl_opflex_tls_11=dict(type="bool"),
        ssl_opflex_tls_12=dict(type="bool"),
        reallocate_gipo=dict(type="bool"),
        restrict_infra_vlan_traffic=dict(type="bool"),
        state=dict(type="str", default="present", choices=["present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=[["ssl_opflex_tls_10", "ssl_opflex_tls_11", "ssl_opflex_tls_12"]],
    )

    aci = ACIModule(module)

    disable_remote_ep_learning = aci.boolean(module.params.get("disable_remote_ep_learning"))
    enforce_subnet_check = aci.boolean(module.params.get("enforce_subnet_check"))
    enforce_epg_vlan_validation = aci.boolean(module.params.get("enforce_epg_vlan_validation"))
    enforce_domain_validation = aci.boolean(module.params.get("enforce_domain_validation"))
    spine_opflex_client_auth = aci.boolean(module.params.get("spine_opflex_client_auth"))
    leaf_opflex_client_auth = aci.boolean(module.params.get("leaf_opflex_client_auth"))
    spine_ssl_opflex = aci.boolean(module.params.get("spine_ssl_opflex"))
    leaf_ssl_opflex = aci.boolean(module.params.get("leaf_ssl_opflex"))
    ssl_opflex_tls_10 = aci.boolean(module.params.get("ssl_opflex_tls_10"))
    ssl_opflex_tls_11 = aci.boolean(module.params.get("ssl_opflex_tls_11"))
    ssl_opflex_tls_12 = aci.boolean(module.params.get("ssl_opflex_tls_12"))
    reallocate_gipo = aci.boolean(module.params.get("reallocate_gipo"))
    restrict_infra_vlan_traffic = aci.boolean(module.params.get("restrict_infra_vlan_traffic"))
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="infraSetPol",
            aci_rn="infra/settings",
            module_object=None,
            target_filter=None,
        ),
    )

    aci.get_existing()

    if state == "present":
        class_config = dict(
            unicastXrEpLearnDisable=disable_remote_ep_learning,
            enforceSubnetCheck=enforce_subnet_check,
            validateOverlappingVlans=enforce_epg_vlan_validation,
            domainValidation=enforce_domain_validation,
            opflexpAuthenticateClients=spine_opflex_client_auth,
            leafOpflexpAuthenticateClients=leaf_opflex_client_auth,
            opflexpUseSsl=spine_ssl_opflex,
            leafOpflexpUseSsl=leaf_ssl_opflex,
            reallocateGipo=reallocate_gipo,
            restrictInfraVLANTraffic=restrict_infra_vlan_traffic,
        )
        if not (ssl_opflex_tls_10 is None and ssl_opflex_tls_11 is None and ssl_opflex_tls_12 is None):
            opflex_tls = []
            if ssl_opflex_tls_10 == "yes":
                opflex_tls.append("TLSv1")
            if ssl_opflex_tls_11 == "yes":
                opflex_tls.append("TLSv1.1")
            if ssl_opflex_tls_12 == "yes":
                opflex_tls.append("TLSv1.2")
            class_config["opflexpSslProtocols"] = ",".join(opflex_tls)

        aci.payload(
            aci_class="infraSetPol",
            class_config=class_config,
        )

        aci.get_diff(aci_class="infraSetPol")

        aci.post_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
