#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_schema_template_anp_epg_subnet
short_description: Manage EPG subnets in schema templates
description:
- Manage EPG subnets in schema templates on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
version_added: '2.8'
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: yes
  template:
    description:
    - The name of the template to change.
    type: str
    required: yes
  anp:
    description:
    - The name of the ANP.
    type: str
    required: yes
  epg:
    description:
    - The name of the EPG to manage.
    type: str
    required: yes
  subnet:
    description:
    - The IP range in CIDR notation.
    type: str
    required: true
    aliases: [ ip ]
  description:
    description:
    - The description of this subnet.
    type: str
  scope:
    description:
    - The scope of the subnet.
    type: str
    choices: [ private, public ]
  shared:
    description:
    - Whether this subnet is shared between VRFs.
    type: bool
  no_default_gateway:
    description:
    - Whether this subnet has a default gateway.
    type: bool
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- Due to restrictions of the MSO REST API concurrent modifications to EPG subnets can be dangerous and corrupt data.
extends_documentation_fragment: mso
'''

EXAMPLES = r'''
- name: Add a new subnet to an EPG
  mso_schema_template_anp_epg_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    subnet: 10.0.0.0/24
    state: present
  delegate_to: localhost

- name: Remove a subnet from an EPG
  mso_schema_template_anp_epg_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    subnet: 10.0.0.0/24
    state: absent
  delegate_to: localhost

- name: Query a specific EPG subnet
  mso_schema_template_anp_epg_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    subnet: 10.0.0.0/24
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all EPGs subnets
  mso_schema_template_anp_epg_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    state: query
  delegate_to: localhost
  register: query_result
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.aci.mso import MSOModule, mso_argument_spec, mso_reference_spec, mso_subnet_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type='str', required=True),
        template=dict(type='str', required=True),
        anp=dict(type='str', required=True),
        epg=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )
    argument_spec.update(mso_subnet_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['subnet']],
            ['state', 'present', ['subnet']],
        ],
    )

    schema = module.params.get('schema')
    template = module.params.get('template')
    anp = module.params.get('anp')
    epg = module.params.get('epg')
    subnet = module.params.get('subnet')
    description = module.params.get('description')
    scope = module.params.get('scope')
    shared = module.params.get('shared')
    no_default_gateway = module.params.get('no_default_gateway')
    state = module.params.get('state')

    mso = MSOModule(module)

    # Get schema
    schema_obj = mso.get_obj('schemas', displayName=schema)
    if not schema_obj:
        mso.fail_json(msg="Provided schema '{0}' does not exist".format(schema))

    schema_path = 'schemas/{id}'.format(**schema_obj)

    # Get template
    templates = [t.get('name') for t in schema_obj.get('templates')]
    if template not in templates:
        mso.fail_json(msg="Provided template '{template}' does not exist. Existing templates: {templates}".format(template=template,
                                                                                                                  templates=', '.join(templates)))
    template_idx = templates.index(template)

    # Get ANP
    anps = [a.get('name') for a in schema_obj.get('templates')[template_idx]['anps']]
    if anp not in anps:
        mso.fail_json(msg="Provided anp '{anp}' does not exist. Existing anps: {anps}".format(anp=anp, anps=', '.join(anps)))
    anp_idx = anps.index(anp)

    # Get EPG
    epgs = [e.get('name') for e in schema_obj.get('templates')[template_idx]['anps'][anp_idx]['epgs']]
    if epg not in epgs:
        mso.fail_json(msg="Provided epg '{epg}' does not exist. Existing epgs: {epgs}".format(epg=epg, epgs=', '.join(epgs)))
    epg_idx = epgs.index(epg)

    # Get Subnet
    subnets = [s.get('ip') for s in schema_obj.get('templates')[template_idx]['anps'][anp_idx]['epgs'][epg_idx]['subnets']]
    if subnet in subnets:
        subnet_idx = subnets.index(subnet)
        # FIXME: Changes based on index are DANGEROUS
        subnet_path = '/templates/{0}/anps/{1}/epgs/{2}/subnets/{3}'.format(template, anp, epg, subnet_idx)
        mso.existing = schema_obj.get('templates')[template_idx]['anps'][anp_idx]['epgs'][epg_idx]['subnets'][subnet_idx]

    if state == 'query':
        if subnet is None:
            mso.existing = schema_obj.get('templates')[template_idx]['anps'][anp_idx]['epgs'][epg_idx]['subnets']
        elif not mso.existing:
            mso.fail_json(msg="Subnet '{subnet}' not found".format(subnet=subnet))
        mso.exit_json()

    subnets_path = '/templates/{0}/anps/{1}/epgs/{2}/subnets'.format(template, anp, epg)
    ops = []

    mso.previous = mso.existing
    if state == 'absent':
        if mso.existing:
            mso.existing = {}
            ops.append(dict(op='remove', path=subnet_path))

    elif state == 'present':
        if not mso.existing:
            if description is None:
                description = subnet
            if scope is None:
                scope = 'private'
            if shared is None:
                shared = False
            if no_default_gateway is None:
                no_default_gateway = False

        payload = dict(
            ip=subnet,
            description=description,
            scope=scope,
            shared=shared,
            noDefaultGateway=no_default_gateway,
        )

        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op='replace', path=subnet_path, value=mso.sent))
        else:
            ops.append(dict(op='add', path=subnets_path + '/-', value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
