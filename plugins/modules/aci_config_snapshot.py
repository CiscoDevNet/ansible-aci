#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_config_snapshot
short_description: Manage Config Snapshots (config:Snapshot, config:ExportP)
description:
- Manage Config Snapshots on Cisco ACI fabrics.
- Creating new Snapshots is done using the configExportP class.
- Removing Snapshots is done using the configSnapshot class.
options:
  description:
    description:
    - The description for the Config Export Policy.
    type: str
    aliases: [ descr ]
  export_policy:
    description:
    - The name of the Export Policy to use for Config Snapshots.
    type: str
    aliases: [ name ]
  format:
    description:
    - Sets the config backup to be formatted in JSON or XML.
    - The APIC defaults to C(json) when unset.
    type: str
    choices: [ json, xml ]
  include_secure:
    description:
    - Determines if secure information should be included in the backup.
    - The APIC defaults to C(yes) when unset.
    type: bool
  max_count:
    description:
    - Determines how many snapshots can exist for the Export Policy before the APIC starts to rollover.
    - Accepted values range between C(1) and C(10).
    - The APIC defaults to C(3) when unset.
    type: int
  snapshot:
    description:
    - The name of the snapshot to delete.
    type: str
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
- The APIC does not provide a mechanism for naming the snapshots.
- 'Snapshot files use the following naming structure: ce_<config export policy name>-<yyyy>-<mm>-<dd>T<hh>:<mm>:<ss>.<mss>+<hh>:<mm>.'
- 'Snapshot objects use the following naming structure: run-<yyyy>-<mm>-<dd>T<hh>-<mm>-<ss>.'
seealso:
- module: cisco.aci.aci_config_rollback
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(config:Snapshot) and B(config:ExportP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Jacob McGill (@jmcgill298)
"""

EXAMPLES = r"""
- name: Create a Snapshot
  cisco.aci.aci_config_snapshot:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: present
    export_policy: config_backup
    max_count: 10
    description: Backups taken before new configs are applied.
  delegate_to: localhost

- name: Query all Snapshots
  cisco.aci.aci_config_snapshot:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query Snapshots associated with a particular Export Policy
  cisco.aci.aci_config_snapshot:
    host: apic
    username: admin
    password: SomeSecretPassword
    export_policy: config_backup
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a Snapshot
  cisco.aci.aci_config_snapshot:
    host: apic
    username: admin
    password: SomeSecretPassword
    export_policy: config_backup
    snapshot: run-2017-08-24T17-20-05
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        description=dict(type="str", aliases=["descr"]),
        export_policy=dict(type="str", aliases=["name"]),  # Not required for querying all objects
        format=dict(type="str", choices=["json", "xml"]),
        include_secure=dict(type="bool"),
        max_count=dict(type="int"),
        snapshot=dict(type="str"),
        state=dict(type="str", choices=["absent", "present", "query"], default="present"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_if=[
            ["state", "absent", ["export_policy", "snapshot"]],
            ["state", "present", ["export_policy"]],
        ],
    )

    aci = ACIModule(module)

    description = module.params.get("description")
    export_policy = module.params.get("export_policy")
    file_format = module.params.get("format")
    include_secure = aci.boolean(module.params.get("include_secure"))
    max_count = module.params.get("max_count")
    if max_count is not None:
        if max_count in range(1, 11):
            max_count = str(max_count)
        else:
            module.fail_json(msg="Parameter 'max_count' must be a number between 1 and 10")
    snapshot = module.params.get("snapshot")
    if snapshot is not None and not snapshot.startswith("run-"):
        snapshot = "run-" + snapshot
    state = module.params.get("state")

    if state == "present":
        aci.construct_url(
            root_class=dict(
                aci_class="configExportP",
                aci_rn="fabric/configexp-{0}".format(export_policy),
                module_object=export_policy,
                target_filter={"name": export_policy},
            ),
        )

        aci.get_existing()

        aci.payload(
            aci_class="configExportP",
            class_config=dict(
                adminSt="triggered",
                descr=description,
                format=file_format,
                includeSecureFields=include_secure,
                maxSnapshotCount=max_count,
                name=export_policy,
                snapshot="yes",
            ),
        )

        aci.get_diff("configExportP")

        # Create a new Snapshot
        aci.post_config()

    else:
        # Prefix the proper url to export_policy
        if export_policy is not None:
            export_policy = "uni/fabric/configexp-{0}".format(export_policy)

        aci.construct_url(
            root_class=dict(
                aci_class="configSnapshotCont",
                aci_rn="backupst/snapshots-[{0}]".format(export_policy),
                module_object=export_policy,
                target_filter={"name": export_policy},
            ),
            subclass_1=dict(
                aci_class="configSnapshot",
                aci_rn="snapshot-{0}".format(snapshot),
                module_object=snapshot,
                target_filter={"name": snapshot},
            ),
        )

        aci.get_existing()

        if state == "absent":
            # Build POST request to used to remove Snapshot
            aci.payload(
                aci_class="configSnapshot",
                class_config=dict(
                    name=snapshot,
                    retire="yes",
                ),
            )

            if aci.existing:
                aci.get_diff("configSnapshot")

                # Mark Snapshot for Deletion
                aci.post_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
