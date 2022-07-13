# Copyright (c) 2022 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
---
author:
- Shreyas Srish (shrsr)
httpapi: aci
short_description: Ansible ACI HTTPAPI Plugin.
description:
  - This ACI plugin provides the HTTPAPI transport methods needed to initiate
    a connection to the APIC, send API requests and process the
    response from the controller.
"""

import json
import re

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils._text import to_text
from ansible.module_utils.connection import ConnectionError
from ansible.plugins.httpapi import HttpApiBase


class HttpApi(HttpApiBase):

    def __init__(self, *args, **kwargs):
        super(HttpApi, self).__init__(*args, **kwargs)
        self.auth = None
        self.check_auth_from_private_key = None
        self.backup_hosts = None
        self.list_of_hosts = []
        self.host_counter = 0
        self.entered_exception = False
        self.exception_message = None
        
    def set_params(self, auth, params):
        self.params = params
        self.auth = auth

    def get_backup_hosts(self):
        try:
            # append is used here to store the first value of the variable self.connection.get_option("host") in the 0th position
            # this is done because we keep changing the value of 'host' constantly when a list of hosts is provided. We always
            # want access to the original set of hosts.
            self.list_of_hosts.append(re.sub(r'[[\]]', '', self.connection.get_option("host")).split(","))
            return self.list_of_hosts
        except Exception:
            return []

    def login(self, username, password):
        ''' Log in to APIC '''
        # Perform login request
        self.connection.queue_message('log', 'Establishing connection to {0}'.format(self.connection.get_option('host')))
        method = 'POST'
        path = '/api/aaaLogin.json'
        payload = {'aaaUser': {'attributes': {'name': username, 'pwd': password}}}
        data = json.dumps(payload)
        try:
            response, response_data = self.connection.send(path, data, method=method)
            response_value = self._get_response_value(response_data)
            self.connection._auth = {'Cookie': 'APIC-Cookie={0}'
                                        .format(self._response_to_json(response_value).get('imdata')[0]['aaaLogin']['attributes']['token'])}
            self.connection.queue_message('vvvv', 'Connection to {0} was successful'.format(self.connection.get_option('host')))
        except Exception as exc:
            self.exception_message = exc
            self.connection.queue_message('vvvv', '{0}'.format(exc))
            self.handle_error()

    def logout(self):
        method = 'POST'
        path = '/api/aaaLogout.json'
        try:
            response, response_data = self.connection.send(path, {}, method=method)
        except Exception as e:
            msg = 'Error on attempt to logout from APIC. {0}'.format(e)
            raise ConnectionError(self._return_info(None, method, path, msg))
        self.connection._auth = None
        self._verify_response(response, method, path, response_data)

    def send_request(self, method, path, data):
        ''' This method handles all APIC REST API requests other than login '''
        if data is None:
            data = {}
        
        # Set backup host/hosts from the inventory if/when provided
        self.get_backup_hosts()
        self.backup_hosts = self.list_of_hosts[0]

        # The command timeout which is the response timeout from APIC can be set in the inventory
        # self.connection.set_option('persistent_command_timeout', 3)

        # Case1: Host is provided in the task of a playbook
        if self.params.get('host') is not None:
            self.connection.set_option("host", self.params.get('host'))

            if self.params.get('port') is not None:
                self.connection.set_option("port", self.params.get('port'))

            if self.params.get('username') is not None:
                self.connection.set_option("remote_user", self.params.get('username'))

            if self.params.get('password') is not None:
                self.connection.set_option("password", self.params.get('password'))

            # Start with certificate authentication (or) Switch from credential authentication to certificate authentication when private key is specified in a 
            # task while ansible is running a playbook.
            if self.auth is not None and self.check_auth_from_private_key is None:
                self.connection._connected = False
                self.connection._auth = {'Cookie': '{0}'.format(self.auth)}
                self.check_auth_from_private_key = {'Cookie': '{0}'.format(self.auth)}
                self.connection.queue_message('vvvv', 'Going through certificate authentication')
                self.connection._connected = True
            
            # Switch from certificate to credential authentication when private key is not specified in a 
            # task while ansible is running a playbook
            elif self.auth is None and self.check_auth_from_private_key is not None:
                self.check_auth_from_private_key = None
                self.connection.queue_message('vvvv', 'Switching from certificate to credential authentication')
                self.connection._connected = False

            if self.params.get('use_proxy') is not None:
                self.connection.set_option("use_proxy", self.params.get('use_proxy'))

            if self.params.get('use_ssl') is not None:
                self.connection.set_option("use_ssl", self.params.get('use_ssl'))

            if self.params.get('validate_certs') is not None:
                self.connection.set_option("validate_certs", self.params.get('validate_certs'))
        
            if self.params.get('timeout') is not None:
                self.connection.set_option('persistent_command_timeout', self.params.get('timeout'))
            
        # Case2: Host is not provided in the task of a playbook
        elif self.backup_hosts:
            try:
                self.connection.set_option("host", self.backup_hosts[self.host_counter])
                self.connection.queue_message('vvvv', 'Initializing operation on host {0}'.format(self.connection.get_option('host')))
            except IndexError:
                pass

        # Initiation of request
        try:
            response, response_data = self.connection.send(path, data, method=method)
            self.connection.queue_message('vvvv', 'Received response from {0} with HTTP: {1}'.format(self.connection.get_option('host'), response.getcode()))
        except Exception as exc:
            self.exception_message = exc
            self.entered_exception = True
            self.connection.queue_message('vvvv', 'Failed to receive response from {0}'.format(self.connection.get_option('host')))
            self.handle_error()
        finally:
            if self.entered_exception:
                self.entered_exception = False
                self.connection.queue_message('vvvv', 'Retrying request on {0}'.format(self.connection.get_option('host')))
                # Final try/except block to close/exit operation
                try:
                    response, response_data = self.connection.send(path, data, method=method)
                    self.connection.queue_message('vvvv', 'Received response from {0} with HTTP: {1}'.format(self.connection.get_option('host'), response.getcode()))
                except:
                    self.connection.queue_message('vvvv', 'Failed to receive response from {0}'.format(self.connection.get_option('host')))
                    self.handle_error()
            return self._verify_response(response, method, path, response_data)

    def handle_error(self):
        # We break the flow of code here when we are operating on a host at task level and/or hosts are also present in the inventory file.
        if self.params.get('host') is not None:
            raise AnsibleConnectionFailure(
                "{0}".format(
                    self.exception_message
                )
            )
        self.host_counter += 1
        if self.host_counter >= len(self.backup_hosts):
            raise ConnectionError("No hosts left in cluster to continue operation!!!")
        self.connection.queue_message('vvvv', 'Switching host from {0} to {1}'.format(self.connection.get_option('host'), self.backup_hosts[self.host_counter]))
        self.connection.set_option("host", self.backup_hosts[self.host_counter])
        self.login(self.connection.get_option("remote_user"), self.connection.get_option("password"))
            
    def _verify_response(self, response, method, path, response_data):
        ''' Process the return code and response object from APIC '''
        response_value = self._get_response_value(response_data)
        if path.find('.json') != -1:
            respond_data = self._response_to_json(response_value)
        else:
            respond_data = response_value
        response_code = response.getcode()
        path = response.geturl()
        if response_code == 400:
            msg = str(response)
        else:
            msg = '{0} ({1} bytes)'.format(response.msg, len(response_value))
        return self._return_info(response_code, method, path, msg, respond_data)

    def _get_response_value(self, response_data):
        ''' Extract string data from response_data returned from APIC '''
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        ''' Convert response_text to json format '''
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except Exception:
            return 'Invalid JSON response: {0}'.format(response_text)

    def _return_info(self, response_code, method, path, msg, respond_data=None):
        ''' Format success/error data and return with consistent format '''
        info = {}
        info['status'] = response_code
        info['method'] = method
        info['url'] = path
        info['msg'] = msg
        info['body'] = respond_data
        return info
