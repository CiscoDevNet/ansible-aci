# Copyright (c) 2020 Cisco and/or its affiliates.
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
from ipaddress import ip_address
__metaclass__ = type

import json
import re
import pickle
import ipaddress

from ansible.module_utils._text import to_text
from ansible.module_utils.connection import ConnectionError
from ansible.plugins.httpapi import HttpApiBase


class HttpApi(HttpApiBase):

    def __init__(self, *args, **kwargs):
        super(HttpApi, self).__init__(*args, **kwargs)
        self.auth = None
        self.check_auth_from_private_key = None
        self.backup_hosts = None
        self.host_counter = 0

    def set_params(self, auth, params):
        self.params = params
        self.auth = auth

    def set_backup_hosts(self):
        try:
            list_of_hosts = re.sub(r'[[\]]', '', self.connection.get_option("host")).split(",")
            ipaddress.ip_address(list_of_hosts[0])
            return list_of_hosts
        except Exception:
            return []

    def login(self, username, password):
        ''' Log in to APIC '''
        # Perform login request
        method = 'POST'
        path = '/api/aaaLogin.json'
        payload = {'aaaUser': {'attributes': {'name': username, 'pwd': password}}}
        data = json.dumps(payload)
        try:
            response, response_data = self.connection.send(path, data, method=method)
            response_value = self._get_response_value(response_data)
            self.connection._auth = {'Cookie': 'APIC-Cookie={0}'
                                        .format(self._response_to_json(response_value).get('imdata')[0]['aaaLogin']['attributes']['token'])}
        except Exception:
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

    def send_request(self, method, path, json):
        ''' This method handles all APIC REST API requests other than login '''
        if json is None:
            json = {}
        # Case1: List of hosts is provided
        if self.host_counter == 0:
            with open('/tmp/hosts.pkl', 'wb') as fi:
                pickle.dump(0, fi)
        self.backup_hosts = self.set_backup_hosts()
        self.connection.set_option('persistent_command_timeout', 1)
        if not self.backup_hosts:
            # if self.connection._connected is True and self.params.get('host') != self.connection.get_option("host"):
            #     self.connection._connected = False
            if self.params.get('host') is not None:
                self.connection.set_option("host", self.params.get('host'))

            if self.params.get('port') is not None:
                self.connection.set_option("port", self.params.get('port'))

            if self.params.get('username') is not None:
                self.connection.set_option("remote_user", self.params.get('username'))

            if self.params.get('password') is not None:
                self.connection.set_option("password", self.params.get('password'))

            if self.auth is not None:
                self.connection._auth = {'Cookie': '{0}'.format(self.auth)}
                self.check_auth_from_private_key = {'Cookie': '{0}'.format(self.auth)}

            if self.params.get('use_proxy') is not None:
                self.connection.set_option("use_proxy", self.params.get('use_proxy'))

            if self.params.get('use_ssl') is not None:
                self.connection.set_option("use_ssl", self.params.get('use_ssl'))

            if self.params.get('validate_certs') is not None:
                self.connection.set_option("validate_certs", self.params.get('validate_certs'))

            #Case2: Switch using private key to credential authentication when private key is not specified
            # if self.auth is None and self.check_auth_from_private_key is not None:
            #     self.login(self.connection.get_option("remote_user"), self.connection.get_option("password"))
        else:
            with open('/tmp/hosts.pkl', 'rb') as fi:
                self.host_counter = pickle.load(fi)
            try:
                self.connection.set_option("host", self.backup_hosts[self.host_counter])
            except IndexError:
                pass
        # Perform some very basic path input validation.
        path = str(path)
        if path[0] != '/':
            msg = 'Value of <path> does not appear to be formated properly'
            raise ConnectionError(self._return_info(None, method, path, msg))
        response = None
        try:
            response, rdata = self.connection.send(path, json, method=method)
            return self._verify_response(response, method, path, rdata)
        except Exception:
            self.handle_error()

    def handle_error(self):
        #raise ConnectionError("login")
        self.host_counter += 1
        if self.host_counter >= len(self.backup_hosts):
            raise ConnectionError("No hosts left in cluster to continue operation %s" % self.connection.get_option("host"))
        with open('/tmp/hosts.pkl', 'wb') as fi:
            pickle.dump(self.host_counter, fi)
        self.connection.set_option("host", self.backup_hosts[self.host_counter])
        self.login(self.connection.get_option("remote_user"), self.connection.get_option("password"))
        return True

    def _verify_response(self, response, method, path, rdata):
        ''' Process the return code and response object from APIC '''
        number = self.host_counter
        resp_value = self._get_response_value(rdata)
        if path.find('.json') != -1:
            respond_data = self._response_to_json(resp_value)
        else:
            respond_data = resp_value
        response_code = response.getcode()
        path = response.geturl()
        if response_code == 400:
            msg = str(response)
        else:
            msg = '{0} ({1} bytes)'.format(response.msg, len(resp_value))
        return self._return_info(response_code, method, path, msg, number, respond_data)

    def _get_response_value(self, response_data):
        ''' Extract string data from response_data returned from APIC '''
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        ''' Convert response_text to json format '''
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except ValueError:
            return 'Invalid JSON response: {0}'.format(response_text)

    def _return_info(self, response_code, method, path, msg, number, respond_data=None):
        ''' Format success/error data and return with consistent format '''
        info = {}
        info['status'] = response_code
        info['method'] = method
        info['url'] = path
        info['msg'] = msg
        info['body'] = respond_data
        info['hosts'] = number
        return info
