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
        self.params = None
        self.check_auth_from_private_key_task = False
        self.check_auth_from_credentials_task = False
        self.check_auth_from_private_key_inventory = False
        self.check_auth_from_credentials_inventory = False
        self.backup_hosts = None
        self.inventory_hosts = []
        self.host_counter = 0
        self.entered_exception = False
        self.connection_error_check = False

    def get_params(self, auth, params):
        self.params = params
        self.auth = auth

    def get_backup_hosts_from_inventory(self):
        # append is used here to store the first list of hosts available in self.connection.get_option("host") in the 0th position of the list inventory_host.
        # This is done because we keep changing the value of 'host' constantly using self.connection.set_option("host") when a list of hosts is provided.
        # We always want access to the original list of hosts from the inventory when the tasks are running on them.
        # Case: Host is provided in the inventory
        self.inventory_hosts.append(re.sub(r'[[\]]', '', self.connection.get_option("host")).split(","))

    # Login function is executed until connection to a host is established or until all the hosts in the list are exhausted 
    def login(self, username, password):
        ''' Log in to APIC '''
        # Perform login request
        self.connection.queue_message('step:', 'Establishing connection to {0}'.format(self.connection.get_option('host')))
        method = 'POST'
        path = '/api/aaaLogin.json'
        payload = {'aaaUser': {'attributes': {'name': username, 'pwd': password}}}
        data = json.dumps(payload)
        try:
            response, response_data = self.connection.send(path, data, method=method)
            response_value = self._get_response_value(response_data)
            self.connection._auth = {'Cookie': 'APIC-Cookie={0}'
                                        .format(self._response_to_json(response_value).get('imdata')[0]['aaaLogin']['attributes']['token'])}
            self.connection.queue_message('step:', 'Connection to {0} was successful'.format(self.connection.get_option('host')))
        except Exception:
            # The exception here is transferred to the response exception
            raise

    def logout(self):
        method = 'POST'
        path = '/api/aaaLogout.json'
        payload = {"aaaUser":{"attributes":{"name":self.connection.get_option("remote_user")}}}
        data = json.dumps(payload)
        try:
            response, response_data = self.connection.send(path, data, method=method)
        except Exception as exc_logout:
            msg = 'Error on attempt to logout from APIC. {0}'.format(exc_logout)
            raise ConnectionError(self._return_info(None, method, path, msg))
        self.connection._auth = None
        self._verify_response(response, method, path, response_data)

    def set_parameters(self, method, path, data):
        if self.params.get('port') is not None:
            self.connection.set_option("port", self.params.get('port'))

        if self.params.get('username') is not None:
            self.connection.set_option("remote_user", self.params.get('username'))
            
        if self.params.get('use_proxy') is not None:
            self.connection.set_option("use_proxy", self.params.get('use_proxy'))

        if self.params.get('use_ssl') is not None:
            self.connection.set_option("use_ssl", self.params.get('use_ssl'))

        if self.params.get('validate_certs') is not None:
            self.connection.set_option("validate_certs", self.params.get('validate_certs'))
    
        # The command timeout which is the response timeout from APIC
        # If the persistent_connect_timeout is less than the response timeout from APIC the persistent socket connection will fail 
        if self.params.get('timeout') is not None:
            self.connection.set_option('persistent_command_timeout', self.params.get('timeout'))
            self.connection.set_option('persistent_connect_timeout', self.params.get('timeout') + 30)
       
        # Start with certificate authentication
        if self.auth is not None:
            # If session_key is present in the inventory, certificate in the task is ignored. In order to avoid this, we explicitly set session_key to None 
            # to give preference to credentials/certificate at the task level. 
            if self.connection.get_option("session_key") is not None:
                self.connection.set_option("session_key", None)
            # Check if the previous task was running with the credentials at the task level/inventory or the certificate in the inventory
            if self.check_auth_from_credentials_task or self.check_auth_from_credentials_inventory or self.check_auth_from_private_key_inventory:
                self.host_counter = 0
                self.check_auth_from_credentials_task = False
                self.check_auth_from_credentials_inventory = False
                self.check_auth_from_private_key_inventory = False
            self.check_auth_from_private_key_task = True
            self.connection._auth = {'Cookie': '{0}'.format(self.auth)}
            self.connection.queue_message('step:', 'Setting certificate authentication at task level')
            # Override parameter in @ensure_connect
            self.connection._connected = True
        # Start with credential authentication
        elif self.params.get('password') is not None:
            # If session_key is present in the inventory, certificate in the task is ignored. In order to avoid this, we explicitly set session_key to None 
            # to give preference to credentials/certificate at the task level. 
            if self.connection.get_option("session_key") is not None:
                self.connection.set_option("session_key", None)
            self.connection.set_option("password", self.params.get('password'))
            # Check if the previous task was running with the certificate in at the task level/inventory or the credentials in the inventory
            if self.check_auth_from_private_key_task or self.check_auth_from_credentials_inventory or self.check_auth_from_private_key_inventory:
                self.host_counter = 0
                # Enforce @ensure_connect
                self.connection._connected = False
                self.check_auth_from_private_key_task = False
                self.check_auth_from_credentials_inventory = False
                self.check_auth_from_private_key_inventory = False
            self.check_auth_from_credentials_task = True
            self.connection.queue_message('step:', 'Setting credential authentication at task level')
        # Note: session_key takes precedence over password if both of them are present in the inventory
        elif self.connection.get_option("session_key") is not None:
            # Check if the previous task was running with the certificate at the task level or the credentials in the inventory/task
            if self.check_auth_from_credentials_inventory or self.check_auth_from_private_key_task or self.check_auth_from_credentials_task:
                self.host_counter = 0
                self.check_auth_from_credentials_inventory = False
                self.check_auth_from_private_key_task = False
                self.check_auth_from_credentials_task = False
            self.check_auth_from_private_key_inventory = True
            self.connection.queue_message('step:', 'Setting certificate authentication from inventory')
            self.connection._auth = {'Cookie': '{0}'.format(self.cert_auth(path, method, data).get('Cookie'))}
            # Override parameter in @ensure_connect
            self.connection._connected = True
        # No session_key provided. Use password in the inventory instead
        else:
            # Check if the previous task was running with the certificate at the task/inventory level or the credentials in the task
            if self.check_auth_from_private_key_inventory or self.check_auth_from_private_key_task or self.check_auth_from_credentials_task:
                self.host_counter = 0
                # Enforce @ensure_connect
                self.connection._connected = False
                self.check_auth_from_private_key_inventory = False
                self.check_auth_from_private_key_task = False
                self.check_auth_from_credentials_task = False
            self.check_auth_from_credentials_inventory = True
            self.connection.queue_message('step:', 'Setting credential authentication from inventory')

    # One API call is made via each call to send_request from aci.py in module_utils
    # As long as a host is active in the list we make sure that the API call goes through
    def send_request(self, method, path, data):
        ''' This method handles all APIC REST API requests other than login '''

        # Note: Preference is given to Hosts mentioned at task level in the playbook
        if self.params.get('host') is not None:
            # Case: Host is provided in the task of a playbook
            task_hosts = ast.literal_eval(self.params.get('host')) if '[' in self.params.get('host') else self.params.get('host').split(",")
            
            # We check whether:
            # 1.The list of hosts provided in two consecutive tasks are not the same
            # 2.connection_error_check was set in the previous task 
            # If yes, we begin the operation on the first host of the list. (Memory of the host in the list-reset).
            # If no, we continue operation on the same host on which previous task was running (Memory of the host in the list-preserved).
            if (self.backup_hosts is not None and self.backup_hosts != task_hosts) or self.connection_error_check:
                self.host_counter = 0
                self.connection_error_check = False
                self.connection._connected = False

            self.backup_hosts = task_hosts
        else:
            # Case: Hosts from the inventory are used
            self.get_backup_hosts_from_inventory()

            # We check whether:
            # 1.The list of hosts provided in two consecutive tasks are not the same
            # 2.connection_error_check was set in the previous task
            # If yes, we begin the operation on the first host of the list. (Memory of the host in the list-reset).
            # If no, we continue operation on the same host on which previous task was running (Memory of the host in the list-preserved).
            if (self.backup_hosts is not None and self.backup_hosts != self.inventory_hosts[0]) or self.connection_error_check:
                self.host_counter = 0
                self.connection_error_check = False
                self.connection._connected = False
    
            # Set backup host/hosts from the inventory. Host is not provided in the task.
            self.backup_hosts = self.inventory_hosts[0]
        
        # Set parameters from the task
        self.set_parameters(method, path, data)
               
        # Start operation on the host
        self.connection.set_option("host", self.backup_hosts[self.host_counter])
        self.connection.queue_message('step:', 'Initializing operation on host {0}'.format(self.connection.get_option('host')))

        # If the credentials are mentioned, the first attempt at login is performed automatically via @ensure_connect before making a request.
        try:
            response, response_data = self.connection.send(path, data, method=method)
            self.connection.queue_message('step:', 'Received response from {0} for {1} operation with HTTP: {2}'.format(self.connection.get_option('host'), method, response.getcode()))
        except Exception as exc_response:
            self.connection.queue_message('step:', 'Connection to {0} has failed: {1}'.format(self.connection.get_option('host'), exc_response))
            self.entered_exception = True
            self.handle_connection_error(exc_response)
            
        # finally block is always executed
        finally: 
            if self.entered_exception:
                self.entered_exception = False
                self.connection.queue_message('step:', 'Retrying request on {0}'.format(self.connection.get_option('host')))
                # Exit recursive function. All the hosts are exhausted
                if not self.connection_error_check:
                    return self.send_request(method, path, data)
        # return statement executed upon each successful response from the request function
        return self._verify_response(response, method, path, response_data)

    # Custom error handler
    def handle_connection_error(self, exception):
        self.host_counter += 1
        if self.host_counter >= len(self.backup_hosts):
            # Base Case for send_request. All hosts are exhausted in the list.
            self.connection_error_check = True
            raise ConnectionError("No hosts left in cluster to continue operation!!! Error on final host {0}: {1}".format(self.connection.get_option('host'), exception))
        self.connection.queue_message('step:', 'Switching host from {0} to {1}'.format(self.connection.get_option('host'), self.backup_hosts[self.host_counter]))
        self.connection.set_option("host", self.backup_hosts[self.host_counter])            
        if self.auth is not None or (self.connection.get_option("session_key") is not None and self.auth is None):
           return
        else:
            # Login function is called until connection to a host is established or until all the hosts in the list are exhausted 
            self.login(self.connection.get_option("remote_user"), self.connection.get_option("password"))

    # Built-in-function
    def handle_httperror(self, exc_http_response):
        self.connection.queue_message('step:', 'Failed to receive response from {0}: {1}'.format(self.connection.get_option('host'), exc_http_response))
        return exc_http_response

    def _verify_response(self, response, method, path, response_data):
        ''' Process the return code and response object from APIC '''
        response_value = self._get_response_value(response_data)
        if path.find('.json') != -1:
            respond_data = self._response_to_json(response_value)
        else:
            respond_data = response_value
        response_code = response.getcode()
        path = response.geturl()
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

        try:
            if HAS_CRYPTOGRAPHY:
                key = list(self.connection.get_option("session_key").values())[0].encode()
                sig_key = serialization.load_pem_private_key(key, password=None, backend=default_backend(),)
            else:
                sig_key = load_privatekey(FILETYPE_PEM, list(self.connection.get_option("session_key").values())[0])
        except Exception:
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
            else:
                raise ConnectionError("Provided private key {0} does not appear to be a private key.".format(list(self.connection.get_option("session_key").values())[0]))    
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
