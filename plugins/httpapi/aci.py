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
__metaclass__ = type

DOCUMENTATION = """
---
author:
- Lionel Hercot (lhercot)
- Shreyas Srish (shrsr)
httpapi: aci
short_description: Ansible ACI HTTPAPI Plugin.
description:
  - This APIC plugin provides the HTTPAPI transport methods needed to initiate
    a connection to the ACI controller, send API requests and process the
    response from the controller.
version_added: "2.1.0"
"""


import json

from ansible.module_utils._text import to_text
from ansible.module_utils.connection import ConnectionError
from ansible.plugins.httpapi import HttpApiBase


class HttpApi(HttpApiBase):

    def __init__(self, *args, **kwargs):
        super(HttpApi, self).__init__(*args, **kwargs)
        self.headers = {
            'Content-Type': "application/json"
        }
        self.auth = None
        self.aci_host = None
        self.aci_user = None
        self.aci_pass = None

    def get_auth(self, auth, host, username, password):
        self.auth = auth
        self.aci_host = host
        self.aci_user = username
        self.aci_pass = password

    def login(self, username, password):
        ''' Log in to APIC '''

        # Perform login request
        method = 'POST'
        path = '/api/aaaLogin.json'
        payload = {'aaaUser': {'attributes': {'name': username, 'pwd': password}}}
        data = json.dumps(payload)
        try:
            response, response_data = self.connection.send(path, data, method=method, headers=self.headers, timeout=10)
            response_value = self._get_response_value(response_data)
            self.connection._auth = {'Cookie': 'APIC-Cookie={0}'
                                     .format(self._response_to_json(response_value).get('imdata')[0]['aaaLogin']['attributes']['token'])}

        except Exception as e:
            msg = 'Error on attempt to connect and authenticate with user: {0} to APIC: {1}. {2} '.format(username, self.connection.get_option("host"), e)
            raise ConnectionError(msg)

    def logout(self):
        method = 'POST'
        path = '/api/aaaLogout.json'

        try:
            response, response_data = self.connection.send(path, {}, method=method, headers=self.headers, force_basic_auth=True)
        except Exception as e:
            msg = 'Error on attempt to logout from APIC. {0}'.format(e)
            raise ConnectionError(self._return_info(None, method, path, msg))

        self._verify_response(response, method, path, response_data)
        # Clean up tokens
        self.connection._auth = None

    def send_request(self, method, path, json=None):
        ''' This method handles all APIC REST API requests other then login '''
        if json is None:
            json = {}

        if self.auth is not None:
            self.connection._auth = {'Cookie': '{0}'
                                     .format(self.auth)}

        if self.aci_host is not None:
            self.connection.set_option("host", self.aci_host)

        if self.aci_user is not None:
            self.connection.set_option("remote_user", self.aci_user)

        if self.aci_pass is not None:
            self.connection.set_option("password", self.aci_pass)

        # Perform some very basic path input validation.
        path = str(path)
        if path[0] != '/':
            msg = 'Value of <path> does not appear to be formated properly'
            raise ConnectionError(self._return_info(None, method, path, msg))

        response, rdata = self.connection.send(path, json, method=method, headers=self.headers)

        return self._verify_response(response, method, path, rdata)

    def _verify_response(self, response, method, path, rdata):
        ''' Process the return code and response object from APIC '''
        resp_value = self._get_response_value(rdata)
        if path.find('.json') != -1:
            respond_data = self._response_to_json(resp_value)
        else:
            respond_data = resp_value
        response_code = response.getcode()
        path = response.geturl()
        msg = response.msg
        return self._return_info(response_code, method, path, msg, respond_data)

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

    def _return_info(self, response_code, method, path, msg, respond_data=None):
        ''' Format success/error data and return with consistent format '''

        info = {}
        info['status'] = response_code
        info['method'] = method
        info['url'] = path
        info['msg'] = msg
        info['body'] = respond_data

        return info
