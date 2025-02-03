# Copyright (c) 2025 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
    name: aci
    short_description: Cisco aci inventory plugin
    extends_documentation_fragment:
      - cisco.aci.aci
      - constructed
    description:
        - Query details from APIC
        - Requires a YAML configuration file whose name ends with 'cisco_aci.(yml|yaml)'
'''

EXAMPLES = '''
---
plugin: cisco.aci.aci
host: 192.168.1.90
username: admin
# You can also use env var ACI_PASSWORD
#password: *******
validate_certs: false
state: query

keyed_groups:
  - prefix: role
    key: role
'''

import os
import atexit
import time
import tempfile
import shutil
import typing as t
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible.module_utils.common.text.converters import to_native
from ansible.errors import AnsibleError
from ansible.utils.display import Display

display = Display()


class MockAnsibleModule(object):
    def __init__(self, argument_spec, parameters):
        """ Mock AnsibleModule

        This is needed in order to use the aci methods which assume to be working
        with a module only.
        """

        self._socket_path = None
        self._debug = False
        self._diff = False
        self._tmpdir = None
        self.check_mode = False
        self.params = dict()

        validator = ArgumentSpecValidator(argument_spec)
        result = validator.validate(parameters)

        if result.error_messages:
            display.vvv("Validation failed: {0}".format(", ".join(result.error_messages)))

        self.params = result.validated_parameters

    @property
    def tmpdir(self):
        # if _ansible_tmpdir was not set and we have a remote_tmp,
        # the module needs to create it and clean it up once finished.
        # otherwise we create our own module tmp dir from the system defaults
        if self._tmpdir is None:
            basedir = None

            if basedir is not None and not os.path.exists(basedir):
                try:
                    os.makedirs(basedir, mode=0o700)
                except (OSError, IOError) as e:
                    self.warn("Unable to use %s as temporary directory, "
                              "failing back to system: %s" % (basedir, to_native(e)))
                    basedir = None
                else:
                    self.warn("Module remote_tmp %s did not exist and was "
                              "created with a mode of 0700, this may cause"
                              " issues when running as another user. To "
                              "avoid this, create the remote_tmp dir with "
                              "the correct permissions manually" % basedir)

            basefile = "ansible-moduletmp-%s-" % time.time()
            try:
                tmpdir = tempfile.mkdtemp(prefix=basefile, dir=basedir)
            except (OSError, IOError) as e:
                self.fail_json(
                    msg="Failed to create remote module tmp path at dir %s "
                        "with prefix %s: %s" % (basedir, basefile, to_native(e))
                )
            atexit.register(shutil.rmtree, tmpdir)
            self._tmpdir = tmpdir

        return self._tmpdir

    def warn(self, warning):
        display.vvv(warning)

    def fail_json(self, msg, **kwargs) -> t.NoReturn:
        raise AnsibleError(msg)


class InventoryModule(BaseInventoryPlugin, Constructable):

    NAME = 'cisco.aci.aci'

    def verify_file(self, path):
        ''' return true/false if this is possibly a valid file for this plugin to consume '''
        valid = False
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current user
            if path.endswith(('cisco_aci.yaml', 'cisco_aci.yml')):
                valid = True
        return valid

    def parse(self, inventory, loader, path, cache=True):

        # call base method to ensure properties are available for use with other helper methods
        super(InventoryModule, self).parse(inventory, loader, path, cache)

        # this method will parse 'common format' inventory sources and
        # update any options declared in DOCUMENTATION as needed
        config = self._read_config_data(path)

        argument_spec = aci_argument_spec()
        argument_spec.update(
            id=dict(type="int", aliases=["controller", "node"]),
            state=dict(type="str", default="query", choices=["query"]),
            keyed_groups=dict(type="list"),
            plugin=dict(type="str"),
        )

        module = MockAnsibleModule(
            argument_spec=argument_spec,
            parameters=config,
        )

        id = module.params.get("id")

        aci = ACIModule(module)
        aci.construct_url(root_class=dict(aci_class="topSystem", target_filter={"id": id}))

        aci.get_existing()

        # parse data and create inventory objects:
        for device in aci.existing:
            attributes = device.get('topSystem').get('attributes')
            self.add_host(attributes['name'], attributes)

    def add_host(self, hostname, host_vars):
        self.inventory.add_host(hostname, group='all')

        if host_vars["oobMgmtAddr"] != "0.0.0.0":
            self.inventory.set_variable(hostname,
                                        "ansible_host",
                                        host_vars["oobMgmtAddr"])
        elif host_vars["inbMgmtAddr"] != "0.0.0.0":
            self.inventory.set_variable(hostname,
                                        "ansible_host",
                                        host_vars["inbMgmtAddr"])
        else:
            self.inventory.set_variable(hostname,
                                        "ansible_host",
                                        host_vars["address"])

        for var_name, var_value in host_vars.items():
            self.inventory.set_variable(hostname, var_name, var_value)

        strict = self.get_option('strict')

        # Add variables created by the user's Jinja2 expressions to the host
        self._set_composite_vars(self.get_option('compose'), host_vars, hostname, strict=True)

        # Create user-defined groups using variables and Jinja2 conditionals
        self._add_host_to_composed_groups(self.get_option('groups'), host_vars, hostname, strict=strict)
        self._add_host_to_keyed_groups(self.get_option('keyed_groups'), host_vars, hostname, strict=strict)
