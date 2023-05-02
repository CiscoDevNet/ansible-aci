#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Tim Cragg (@timcragg) <tcragg@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_aaa_pre_login_banner
short_description: Manage AAA login banner (aaa:PreLoginBanner)
description:
- Manage AAA login banner on Cisco ACI fabrics.
options:
  description:
    description:
    - The description of the AAA login banner.
    type: str
  banner_message:
    description:
    - The Application Banner Message.
    type: str
  banner_message_severity:
    description:
    - The Application Banner Severity.
    - The APIC defaults to C(info) when unset during creation.
    type: str
    choices: [ critical, info, major, minor, warning ]
  gui_message:
    description:
    - The contents of the GUI informational banner to be displayed before user login authentication.
    - The value is defined as a URL of a site hosting the desired HTML.
    - The I(http://) or I(https://) prefix does not need to be included.
    - Note that the URL site owner must allow the site to be placed in an iFrame to display the informational banner.
    type: str
  gui_message_text:
    description:
    - The login GUI string message.
    type: str
  is_gui_message_text:
    description:
    - Use text-based pre-login GUI banner message.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  gui_message_proto:
    description:
    - The protocol used for the GUI message.
    - This is only used when is_gui_message_text is C(false), and gui_message does not start with either http:// or https://
    type: str
    choices: [ http, https ]
    default: https
  cli_message:
    description:
    - The contents of the CLI informational banner to be displayed before user login authentication.
    - The CLI banner is a text based string printed as-is to the console.
    - The APIC defaults to I(Application Policy Infrastructure Controller) when unset during creation.
    type: str
  show_banner_message:
    description:
    - Whether to show the application banner.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  switch_message:
    description:
    - The Switch Login Banner Message.
    type: str
  state:
    description:
    - Use C(present) for updating.
    - Use C(query) for listing an object.
    type: str
    choices: [ present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(aaa:PreLoginBanner).
  link: https://developer.cisco.com/docs/apic-mim-ref/

author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Configure AAA login banner
  cisco.aci.aci_aaa_pre_login_banner:
    host: apic
    username: admin
    password: SomeSecretPassword
    banner_message: Test Banner Message
    switch_message: Test Switch Banner Message
    gui_message_text: Test GUI Banner Message
    is_gui_message_text: yes
    state: present
  delegate_to: localhost

- name: Query AAA login banner
  cisco.aci.aci_aaa_pre_login_banner:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_remote_path
    state: query
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
        description=dict(type="str"),
        banner_message=dict(type="str"),
        banner_message_severity=dict(type="str", choices=["critical", "info", "major", "minor", "warning"]),
        gui_message=dict(type="str"),
        gui_message_text=dict(type="str"),
        is_gui_message_text=dict(type="bool"),
        gui_message_proto=dict(type="str", default="https", choices=["http", "https"]),
        cli_message=dict(type="str"),
        show_banner_message=dict(type="bool"),
        switch_message=dict(type="str"),
        state=dict(type="str", default="present", choices=["present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    aci = ACIModule(module)

    description = module.params.get("description")
    banner_message = module.params.get("banner_message")
    banner_message_severity = module.params.get("banner_message_severity")
    gui_message = module.params.get("gui_message")
    gui_message_text = module.params.get("gui_message_text")
    is_gui_message_text = aci.boolean(module.params.get("is_gui_message_text"))
    gui_message_proto = module.params.get()
    message = module.params.get("cli_message")
    show_banner_message = aci.boolean(module.params.get("show_banner_message"))
    switch_message = module.params.get("switch_message")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="aaaPreLoginBanner",
            aci_rn="userext/preloginbanner",
        ),
    )
    aci.get_existing()

    if state == "present":
        if gui_message is not None and is_gui_message_text == "no" and not gui_message.startswith(("http://", "https://")):
            gui_message = "{0}://{1}".format(gui_message_proto, gui_message)

        aci.payload(
            aci_class="aaaPreLoginBanner",
            class_config=dict(
                descr=description,
                bannerMessage=banner_message,
                bannerMessageSeverity=banner_message_severity,
                guiMessage=gui_message,
                guiTextMessage=gui_message_text,
                isGuiMessageText=is_gui_message_text,
                message=message,
                showBannerMessage=show_banner_message,
                switchMessage=switch_message,
            ),
        )

        aci.get_diff(aci_class="aaaPreLoginBanner")

        aci.post_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
