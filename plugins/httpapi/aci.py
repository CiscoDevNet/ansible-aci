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

import base64
import json
import os
import collections
import requests
import sys
import re
import traceback
from copy import deepcopy

from ansible.module_utils._text import to_text
from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import to_list
from ansible.plugins.httpapi import HttpApiBase

#from ansible_collections.ansible.netcommon.plugins.connection import httpapi
from ansible.playbook.play_context import PlayContext
from ansible.playbook import play_context
from ansible.parsing.dataloader import DataLoader
from ansible.vars.manager import VariableManager
from ansible.inventory.manager import InventoryManager
from ansible.plugins.loader import httpapi_loader
from ansible.module_utils._text import to_bytes, to_native


class HttpApi(HttpApiBase):

    def __init__(self, *args, **kwargs):
        super(HttpApi, self).__init__(*args, **kwargs)
        self.headers = {
            'Content-Type': "application/json"
        }

    def handle_httperror(self, exc):
        return self._return_error(exc.code, exc)
            
    def login(self, username, password):
        ''' Log in to APIC '''
        # Perform login request
        method = 'POST'
        path = '/api/aaaLogin.json'
        if username is None or password is None:
            raise ConnectionError("Invalid username/password")
        payload = {'aaaUser': {'attributes': {'name': username, 'pwd': password}}}
        # timeout = self.connection.get_option("persistent_connect_timeout") * 1000
        # data = "{'expirationTime': %s}" % timeout
        data = json.dumps(payload)
        #raise ConnectionError(self.connection.get_option("network_os"))
        #host = self.connection.get_option("host")
        try:
            response, response_data = self.connection.send(path, data, method=method, headers=self.headers, timeout=10)
            response_value = self._get_response_value(response_data)
            self.connection._auth = {'Cookie': 'APIC-Cookie={0}'
                                     .format(self._response_to_json(response_value).get('imdata')[0]['aaaLogin']['attributes']['token'])}

        except Exception as e:
            msg = 'Error on attempt to connect and authenticate with user {0} to APIC: {1} '.format(username, e)

    def logout(self):
        method = 'POST'
        path = '/api/aaaLogout.json'

        try:
            response, response_data = self.connection.send(path, {}, method=method, headers=self.headers, force_basic_auth=True)
        except Exception as e:
            msg = 'Error on attempt to logout from APIC controller: {0}'.format(e)
            raise ConnectionError(self._return_info(None, method, path, msg))

        self._verify_response(response, method, path, response_data, rest_type='json')
        # Clean up tokens
        self.connection._auth = None

    def send_request(self, method, path, json=None):
        ''' This method handles all APIC REST API requests other then login '''
        if json is None:
            json = {}
        #self.connection.set_option("host","10.23.248.116")
        try:
            # Perform some very basic path input validation.
            path = str(path)
            if path[0] != '/':
                msg = 'Value of <path> does not appear to be formated properly'
                raise ConnectionError(self._return_info(None, method, path, msg))
            response, rdata = self.connection.send(path, json, method=method,
                                                   headers=self.headers,
                                                   force_basic_auth=True)
            if path.find('.json') != -1:
                return self._verify_response(response, method, path, rdata, rest_type='json')
            else:
                return self._verify_response(response, method, path, rdata, rest_type='xml')

        except Exception as e:
            pass
            # TO DO

    def _verify_response(self, response, method, path, rdata, rest_type):
        ''' Process the return code and response object from APIC '''
        resp_value = self._get_response_value(rdata)
        if rest_type == 'json':
            respond_data = self._response_to_json(resp_value)
        else:
            respond_data = resp_value
        response_code = response.getcode()
        path = response.geturl()
        msg = response.msg
        # Handle APIC response
        if response_code == 200:
            return self._return_info(response_code, method, path, msg, respond_data)
        else:
            # Never Reaches Here because of httperror exception in httpapi module
           pass

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

    def _return_error(self, code, response):
        error = {}
        error['status'] = code
        # error['method'] = method
        # error['url'] = path
        # error['msg'] = msg
        error['body'] = response

        return error
