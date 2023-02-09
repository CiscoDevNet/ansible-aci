#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Tim Cragg (@timcragg) <tcragg@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_file_remote_path
short_description: Manage Import/Export File Remote Paths (file:RemotePath)
description:
- Manage Import/Export File Remote Paths on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the File Remote Path.
    type: str
  description:
    description:
    - Description of the File Remote Path
    type: str
  remote_host:
    description:
    - Hostname or IP Address of the remote host
    type: str
  remote_port:
    description:
    - Port to access the remote host
    type: int
  remote_protocol:
    description:
    - Protocol to use to connect to the remote host
    choices: [ ftp, scp, sftp ]
  auth_type:
    description:
    - Authentication type for the remote host. Cannot be set to C(ssh_key) if C(protocol) is C(ftp)
    type: str
    choices: [ password, ssh_key ]
  remote_user:
    description:
    - Username to access the remote host.
    type: str
  remote_password:
    description:
    - Password to access the remote host. Only used if C(auth_type) is C(password)
    type: str
  private_key_contents:
    description:
    - Private SSH key used to access the remote host. Only used if C(auth_type) is C(ssh_key)
    type: str
    aliases: [ private_key, key ]
  private_key_passphrase:
    description:
    - Pass phrase used to decode C(private_key_contents). Only used if C(auth_type) is C(ssh_key)
    type: str
    aliases: [ passphrase ]
  remote_path:
    description:
    - Path on which the data will reside on the remote host
    type: str
  management_epg:
    description:
    - Management EPG to connect to the remote host on
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(file:RemotePath).
  link: https://developer.cisco.com/docs/apic-mim-ref/

author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a Remote Path
  cisco.aci.aci_file_remote_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_remote_path
    remote_host: test.example.com
    protocol: scp
    remote_user: test_user
    auth_type: password
    remote_password: test_pass
    remote_path: /tmp
    state: present
  delegate_to: localhost

- name: Query a Remote Path
  cisco.aci.aci_file_remote_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_remote_path
    state: query
  delegate_to: localhost

- name: Query all Remote Paths
  cisco.aci.aci_file_remote_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Remove a Remote Path
  cisco.aci.aci_file_remote_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_remote_path
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
        name=dict(type="str"),
        description=dict(type="str"),
        remote_host=dict(type="str"),
        remote_port=dict(type="int"),
        remote_protocol=dict(type="str", choices=["ftp", "scp", "sftp"]),
        remote_path=dict(type="str"),
        auth_type=dict(type="str", choices=["password", "ssh_key"]),
        remote_user=dict(type="str"),
        remote_password=dict(type="str", no_log=True),
        private_key_contents=dict(type="str", aliases=["private_key", "key"], no_log=True),
        private_key_passphrase=dict(type="str", aliases=["passphrase"], no_log=True),
        management_epg=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["name", "auth_type"]],
            ["state", "absent", ["name"]],
        ],
    )

    name = module.params.get("name")
    description = module.params.get("description")
    remote_host = module.params.get("remote_host")
    remote_port = module.params.get("remote_port")
    remote_protocol = module.params.get("remote_protocol")
    remote_path = module.params.get("remote_path")
    auth_type = module.params.get("auth_type")
    remote_user = module.params.get("remote_user")
    remote_password = module.params.get("remote_password")
    private_key_contents = module.params.get("private_key_contents")
    private_key_passphrase = module.params.get("private_key_passphrase")
    management_epg = module.params.get("management_epg")
    state = module.params.get("state")

    if auth_type == "password":
        if private_key_contents is not None:
            aci.fail_json(msg="private_key_contents cannot be set if auth_type is password")
        if private_key_passphrase is not None:
            aci.fail_json(msg="private_key_passphrase cannot be set if auth_type is password")
        auth = "usePassword"
    elif auth_type == "ssh_key":
        if remote_password is not None:
            aci.fail_json(msg="remote_password cannot be set if auth_type is ssh_key")
        auth = "useSshKeyContents"
    else:
        auth = None

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fileRemotePath",
            aci_rn="fabric/path-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=["fileRsARemoteHostToEpg"]
    )
    aci.get_existing()

    if state == "present":
        child_configs = []
        if management_epg is not None:
            child_configs.append(
                dict(
                    fileRsARemoteHostToEpg=dict(
                        attributes=dict(tDn=("uni/tn-mgmt/mgmtp-default/{0}".format(management_epg))),
                    )
                )
            )
        aci.payload(
            aci_class="fileRemotePath",
            class_config=dict(
                name=name,
                descr=description,
                authType=auth,
                host=remote_host,
                protocol=remote_protocol,
                remotePath=remote_path,
                remotePort=remote_port,
                userName=remote_user,
                userPasswd=remote_password,
                identityPrivateKeyContents=private_key_contents,
                identityPrivateKeyPassphrase=private_key_passphrase,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="fileRemotePath")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
