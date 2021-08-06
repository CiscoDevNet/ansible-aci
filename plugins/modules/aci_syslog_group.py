#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = r'''
---
module: aci_syslog_group
short_description: Manage Syslog groups (syslog:Group, syslog:Console, syslog:File and syslog:Prof).
description:
- Manage syslog groups
options:
  admin_state:
    description:
    - Administrative state of the syslog group
    type: str
    choices: [ enabled, disabled ]
  console_logging:
    description:
    - Log events to console
    type: str
    choices: [ enabled, disabled ]
  console_log_severity:
    description:
    - Severity of events to log to console
    type: str
    choices: [ alerts, critical, debugging, emergencies, error, information, notifications, warnings ]
  local_file_logging:
    description:
    - Log to local file
    type: str
    choices: [ enabled, disabled ]
  local_file_log_severity:
    description:
    - Severity of events to log to local file
    type: str
    choices: [ alerts, critical, debugging, emergencies, error, information, notifications, warnings ]
  format:
    description:
    - Format of the syslog messages. If omitted when creating a group, ACI defaults to using aci format.
    type: str
    choices: [ aci, nxos ]
  include_ms:
    description:
    - Include milliseconds in log timestamps
    type: bool
  include_time_zone:
    description:
    - Include timezone in log timestamps
    type: bool
  name:
    description:
    - Name of the syslog group
    type: str
    aliases: [ syslog_group, syslog_group_name ]
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
  description: More information about the internal APIC classes B(syslog:Group).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
'''

EXAMPLES = r'''
- name: Create a syslog group
  cisco.aci.aci_syslog_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_syslog_group
    local_file_logging: enabled
    local_file_log_severity: warnings
    console_logging: enabled
    console_log_severity: critical
    state: present
  delegate_to: localhost

- name: Disable logging to local file
  cisco.aci.aci_syslog_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_syslog_group
    local_file_logging: disabled
    state: present
  delegate_to: localhost

- name: Remove a syslog group
  cisco.aci.aci_syslog_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_syslog_group
    state: absent
  delegate_to: localhost

- name: Query a syslog group
  cisco.aci.aci_syslog_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_syslog_group
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all syslog groups
  cisco.aci.aci_syslog_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result
'''

RETURN = r'''
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
'''


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        name=dict(type='str', aliases=['syslog_group', 'syslog_group_name']),
        format=dict(type='str', choices=['aci', 'nxos']),
        admin_state=dict(type='str', choices=['enabled', 'disabled']),
        console_logging=dict(type='str', choices=['enabled', 'disabled']),
        console_log_severity=dict(type='str',
                                  choices=['alerts', 'critical', 'debugging',
                                           'emergencies', 'error',
                                           'information', 'notifications',
                                           'warnings']),
        local_file_logging=dict(type='str', choices=['enabled', 'disabled']),
        local_file_log_severity=dict(type='str',
                                     choices=['alerts', 'critical', 'debugging',
                                              'emergencies', 'error',
                                              'information', 'notifications',
                                              'warnings']),
        include_ms=dict(type='bool'),
        include_time_zone=dict(type='bool'),
        state=dict(type='str', default='present',
                   choices=['absent', 'present', 'query'])
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['name']],
            ['state', 'present', ['name']],
        ]
    )

    aci = ACIModule(module)

    name = module.params.get('name')
    format = module.params.get('format')
    admin_state = module.params.get('admin_state')
    console_logging = module.params.get('console_logging')
    console_log_severity = module.params.get('console_log_severity')
    local_file_logging = module.params.get('local_file_logging')
    local_file_log_severity = module.params.get('local_file_log_severity')
    include_ms = aci.boolean(module.params.get('include_ms'))
    include_time_zone = aci.boolean(module.params.get('include_time_zone'))
    state = module.params.get('state')

    aci.construct_url(
        root_class=dict(
            aci_class='syslogGroup',
            aci_rn='fabric/slgroup-{0}'.format(name),
            module_object=name,
            target_filter={'name': name},
        ),
        child_classes=['syslogRemoteDest', 'syslogProf', 'syslogFile',
                       'syslogConsole'],
    )

    aci.get_existing()

    if state == 'present':
        class_config = dict(
            name=name,
            format=format,
            includeMilliSeconds=include_ms,
        )
        if include_time_zone is not None:
            class_config['includeTimeZone'] = include_time_zone
        aci.payload(
            aci_class='syslogGroup',
            class_config=class_config,
            child_configs=[
                dict(
                    syslogProf=dict(
                        attributes=dict(
                            adminState=admin_state,
                            name='syslog'
                        ),
                    ),
                ),
                dict(
                    syslogFile=dict(
                        attributes=dict(
                            adminState=local_file_logging,
                            format=format,
                            severity=local_file_log_severity
                        ),
                    ),
                ),
                dict(
                    syslogConsole=dict(
                        attributes=dict(
                            adminState=console_logging,
                            format=format,
                            severity=console_log_severity
                        ),
                    ),
                ),
            ],
        )

        aci.get_diff(aci_class='syslogGroup')

        aci.post_config()

    elif state == 'absent':
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
