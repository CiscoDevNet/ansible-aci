#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_export_encryption
short_description: Manage Global AES Passphrase Encryption Settings (pki:ExportEncryptionKey)
description:
- Manage Global AES Passphrase Encryption Settings on Cisco ACI fabrics.
options:
  passphrase:
    description:
    - The AES passphrase to use for configuration export encryption.
    - This cannot be modified once in place on the APIC. To modify an existing passphrase, you must delete it by sending a request with state C(absent).
    - The value of the passphrase will not be shown in the results of a C(query).
    type: str
  strong_encryption:
    description:
    - Enable strong encryption.
    - This defaults to False on the APIC when unset during creation.
    - Note that this will be set back to False when deleting an existing passphrase.
    type: bool
  state:
    description:
    - Use C(present) to create a passphrase or to change the strong_encryption setting.
    - Use C(absent) to delete the existing passphrase.
    - Use C(query) for showing current configuration.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(pki:ExportEncryptionKey).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Set a passphrase
  cisco.aci.aci_export_encryption:
    host: apic
    username: admin
    password: SomeSecretPassword
    passphrase: ansible_passphrase
    strong_encryption: yes
    state: present
  delegate_to: localhost

- name: Query passphrase settings
  cisco.aci.aci_export_encryption:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete passphrase
  cisco.aci.aci_export_encryption:
    host: apic
    username: admin
    password: SomeSecretPassword
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        passphrase=dict(type="str", no_log=True),
        strong_encryption=dict(type="bool"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    aci = ACIModule(module)

    passphrase = module.params.get("passphrase")
    strong_encryption = aci.boolean(module.params.get("strong_encryption"))
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="pkiExportEncryptionKey",
            aci_rn="exportcryptkey",
            module_object=None,
            target_filter=None,
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="pkiExportEncryptionKey",
            class_config=dict(
                passphrase=passphrase,
                strongEncryptionEnabled=strong_encryption,
            ),
        )

        aci.get_diff(aci_class="pkiExportEncryptionKey")

        aci.post_config()

    elif state == "absent":
        aci.payload(
            aci_class="pkiExportEncryptionKey",
            class_config=dict(
                clearEncryptionKey="yes",
            ),
        )

        aci.get_diff(aci_class="pkiExportEncryptionKey")

        aci.post_config()

    aci.exit_json()


if __name__ == "__main__":
    main()