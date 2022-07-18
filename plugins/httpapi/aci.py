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
from importlib.resources import path
from operator import methodcaller
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

import ast, base64, json, os, re

from ansible.module_utils._text import to_text, to_native
from ansible.module_utils.connection import ConnectionError
from ansible.plugins.httpapi import HttpApiBase

# Optional, only used for APIC signature-based authentication
try:
    from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, sign
    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False

# Signature-based authentication using cryptography
try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class HttpApi(HttpApiBase):

    def __init__(self, *args, **kwargs):
        super(HttpApi, self).__init__(*args, **kwargs)
        self.auth = None
        self.check_auth_from_private_key = False
        self.backup_hosts = None
        self.list_of_hosts = []
        self.host_counter = 0
        self.counter_checker = False
        self.entered_exception = False
        self.exception_message = None
        self.response_auth = None
        self.response_data_auth = None

    def get_params(self, auth, params, method, call_path, data):
        self.params = params
        self.auth = auth
        self.method = method
        self.call_path = call_path
        self.data = data

    def get_backup_hosts_from_inventory(self):
        try:
            # append is used here to store the list of hosts in self.connection.get_option("host") in the 0th position.
            # This is done because we keep changing the value of 'host' constantly using self.connection.set_option("host") when a list of hosts is provided.
            # We always want access to the original list of hosts.

            # Case: Host is provided in the inventory
            self.list_of_hosts.append(re.sub(r'[[\]]', '', self.connection.get_option("host")).split(","))
        except Exception:
            pass

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
        except Exception as exc:
            msg = 'Error on attempt to logout from APIC. {0}'.format(exc)
            raise ConnectionError(self._return_info(None, method, path, msg))
        self.connection._auth = None
        self._verify_response(response, method, path, response_data)

    def send_request(self, method, path, data):
        ''' This method handles all APIC REST API requests other than login '''

        # The command timeout which is the response timeout from APIC can be set in the inventory
        # self.connection.set_option('persistent_command_timeout', 3)

        if self.params.get('host') is not None:

            # Case: Host is provided in the task of a playbook
            # We check if the list of hosts provided in two consecutive tasks are the same. If they are not the same we begin operation from the first host on the next 
            # task (Memory of the host in the list-reset).
            # If they are the same, we continue operation on the same host on which previous task was running (Memory of the host in the list-preserved).
            if self.backup_hosts != ast.literal_eval(self.params.get('host')) if '[' in self.params.get('host') else self.params.get('host').split(",") or not self.counter_checker:
                self.host_counter = 0

            self.backup_hosts = ast.literal_eval(self.params.get('host')) if '[' in self.params.get('host') else self.params.get('host').split(",")

            if self.params.get('port') is not None:
                self.connection.set_option("port", self.params.get('port'))

            if self.params.get('username') is not None:
                self.connection.set_option("remote_user", self.params.get('username'))

            if self.params.get('password') is not None:
                self.connection.set_option("password", self.params.get('password'))

            # Start with certificate authentication (or) Switch from credential authentication to certificate authentication when private key is specified in a
            # task while ansible is running a playbook.
            if self.auth is not None:
                self.connection._auth = {'Cookie': '{0}'.format(self.auth)}
                self.check_auth_from_private_key = True
                self.connection.queue_message('vvvv', 'Going through certificate authentication')
                # Override @ensure_connect check
                self.connection._connected = True

            # Switch from certificate to credential authentication when private key is not specified in a
            # task while ansible is running a playbook
            elif self.auth is None and self.check_auth_from_private_key:
                self.check_auth_from_private_key = False
                # Continue Operation on the host via credential authentication. Memory of the host in the list-preserved.
                self.connection.queue_message('vvvv', 'Switching from certificate to credential authentication')
                self.connection.set_option("host", self.backup_hosts[self.host_counter])
                self.login(self.connection.get_option("remote_user"), self.connection.get_option("password"))

            if self.params.get('use_proxy') is not None:
                self.connection.set_option("use_proxy", self.params.get('use_proxy'))

            if self.params.get('use_ssl') is not None:
                self.connection.set_option("use_ssl", self.params.get('use_ssl'))

            if self.params.get('validate_certs') is not None:
                self.connection.set_option("validate_certs", self.params.get('validate_certs'))

            if self.params.get('timeout') is not None:
                self.connection.set_option('persistent_command_timeout', self.params.get('timeout'))

            self.counter_checker = True

        else:
            # Reset counter to start operation on first host in inventory. Memory of the host in the list-reset.
            # This covers the scenario where a playbook contains back to back tasks with and without hosts specified at task level.
            if self.counter_checker:
                self.host_counter = 0
                self.counter_checker = False
            # Set backup host/hosts from the inventory. Host is not provided in the task.
            self.get_backup_hosts_from_inventory()
            self.backup_hosts = self.list_of_hosts[0]
            # Note: session_key takes precedence over password
            if self.connection.get_option("session_key") is not None:
                self.connection._auth = {'Cookie': '{0}'.format(self.cert_auth(path, method, data).get('Cookie'))}
                self.connection.queue_message('vvvv', 'Going through certificate authentication')
                # Override @ensure_connect check
                self.connection._connected = True

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
            self.connection.queue_message('vvvv', 'Failed to receive response from {0}: {1}'.format(self.connection.get_option('host'), exc))
            self.handle_error()
        finally:
            if self.entered_exception:
                self.entered_exception = False
                if self.auth is not None or (self.connection.get_option("session_key") is not None and self.auth is None):
                    if self.host_counter >= len(self.backup_hosts):
                        raise ConnectionError("No hosts left in cluster to continue operation!!! Error on final host: {0}".format(self.exception_message))
                    self.connection.queue_message('vvvv', 'Received response from {0} with HTTP: {1}'.format(self.connection.get_option('host'),
                                                  self.response_auth.getcode()))
                    return self._verify_response(self.response_auth, self.method, self.call_path, self.response_data_auth)
                self.connection.queue_message('vvvv', 'Retrying request on {0}'.format(self.connection.get_option('host')))
                # Final try/except block to close/exit operation
                try:
                    response, response_data = self.connection.send(path, data, method=method)
                    self.connection.queue_message('vvvv', 'Received response from {0} with HTTP: {1}'.format(self.connection.get_option('host'),
                                                  response.getcode()))
                except Exception as exc:
                    self.exception_message = exc
                    self.handle_error()
        return self._verify_response(response, method, path, response_data)

    def handle_error(self):
        # We break the flow of code here when we are operating on a single host at task level or single host in the inventory file.
        # We do this to replicate the behavior of Ansible running via local connection on a single host.
        if len(self.backup_hosts) == 1:
            raise ConnectionError("{0}".format(self.exception_message))
        self.host_counter += 1
        if self.host_counter >= len(self.backup_hosts):
            raise ConnectionError("No hosts left in cluster to continue operation!!! Error on final host: {0}".format(self.exception_message))
        self.connection.queue_message('vvvv', 'Switching host from {0} to {1}'.format(self.connection.get_option('host'), self.backup_hosts[self.host_counter]))
        self.connection.set_option("host", self.backup_hosts[self.host_counter])
        
        if self.auth is not None or (self.connection.get_option("session_key") is not None and self.auth is None):
            self.connection.queue_message('vvvv', 'Retrying request on {0}'.format(self.connection.get_option('host')))
            try:
                response_auth, response_data_auth = self.connection.send(self.call_path, self.data, method=self.method)
                self.response_auth = response_auth
                self.response_data_auth = response_data_auth
            except Exception as exc:
                self.exception_message = exc
                self.connection.queue_message('vvvv', 'Failed to receive response from {0}: {1}'.format(self.connection.get_option('host'), exc))
                self.handle_error()
        else:
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

    def cert_auth(self, path, method, payload=''):
        ''' Perform APIC signature-based authentication, not the expected SSL client certificate authentication. '''

        headers = dict()

        if payload is None:
            payload = ''

        if os.path.exists(list(self.connection.get_option("session_key").values())[0]):
            try:
                permission = 'r'
                if HAS_CRYPTOGRAPHY:
                    permission = 'rb'
                with open(list(self.connection.get_option("session_key").values())[0], permission) as fh:
                    private_key_content = fh.read()
            except Exception:
                raise ConnectionError("Cannot open private key file {0}".format(list(self.connection.get_option("session_key").values())[0]))
            try:
                if HAS_CRYPTOGRAPHY:
                    sig_key = serialization.load_pem_private_key(private_key_content, password=None, backend=default_backend(),)
                else:
                    sig_key = load_privatekey(FILETYPE_PEM, private_key_content)
            except Exception:
                raise ConnectionError("Cannot load private key file {0}".format(list(self.connection.get_option("session_key").values())[0]))
            self.params['certificate_name'] = list(self.connection.get_option("session_key").keys())[0]
        sig_request = method + path + payload
        if HAS_CRYPTOGRAPHY:
            sig_signature = sig_key.sign(sig_request.encode(), padding.PKCS1v15(), hashes.SHA256())
        else:
            sig_signature = sign(sig_key, sig_request, 'sha256')
        sig_dn = 'uni/userext/user-{0}/usercert-{1}'.format(self.connection.get_option("remote_user"), list(self.connection.get_option("session_key").keys())[0])
        headers['Cookie'] = 'APIC-Certificate-Algorithm=v1.0; ' +\
                                 'APIC-Certificate-DN=%s; ' % sig_dn +\
                                 'APIC-Certificate-Fingerprint=fingerprint; ' +\
                                 'APIC-Request-Signature=%s' % to_native(base64.b64encode(sig_signature))
        return headers
