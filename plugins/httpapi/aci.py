# Copyright (c) 2022 Cisco and/or its affiliates.
# Copyright: (c) 2020, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
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


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
name: aci
author:
- Shreyas Srish (@shrsr)
short_description: Ansible ACI HTTPAPI Plugin.
description:
  - This ACI plugin provides the HTTPAPI transport methods needed to initiate
    a connection to the APIC, send API requests and process the
    response from the controller.
"""

import ast
import base64
import json
import os
import re

from ansible.module_utils._text import to_text, to_native
from ansible.module_utils.connection import ConnectionError
from ansible.plugins.httpapi import HttpApiBase
from copy import copy

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

CONNECTION_MAP = {"username": "remote_user", "timeout": "persistent_command_timeout"}
RESET_KEYS = ["username", "password", "port"]
CONNECTION_KEYS = RESET_KEYS + ["timeout", "use_proxy", "use_ssl", "validate_certs"]

class HttpApi(HttpApiBase):
    def __init__(self, *args, **kwargs):
        super(HttpApi, self).__init__(*args, **kwargs)
        self.auth = None
        self.params = None
        self.result = {}
        self.check_authentication = ""
        self.backup_hosts = None
        self.inventory_hosts = []
        self.host_counter = 0
        self.connection_error_check = False
        self.connection_parameters = {}
        self.begin_task = False
        self.executed_exit_function = False
        self.current_host = None
        self.provided_hosts = None
        self.get_first_item = []

    def set_params(self, auth, params):
        self.params = params
        self.auth = auth

    # Login function is executed until connection to a host is established or until all the hosts in the list are exhausted
    def login(self, username, password):
        """Log in to APIC"""
        # Perform login request
        self.connection.queue_message("step:", "Establishing login to {0}".format(self.connection.get_option("host")))
        method = "POST"
        path = "/api/aaaLogin.json"
        payload = {"aaaUser": {"attributes": {"name": username, "pwd": password}}}
        data = json.dumps(payload)
        try:
            response, response_data = self.connection.send(path, data, method=method)
            response_value = self._get_response_value(response_data)
            self.connection._auth = {
                "Cookie": "APIC-Cookie={0}".format(self._response_to_json(response_value).get("imdata")[0]["aaaLogin"]["attributes"]["token"])
            }
            self.connection.queue_message("step:", "Connection to {0} was successful".format(self.connection.get_option("host")))
        except Exception as exc_response:
            self.connection.queue_message("step:", "Connection to {0} has failed: {1}".format(self.connection.get_option("host"), exc_response))
            self.handle_connection_error(exc_response)

    def logout(self):
        method = "POST"
        path = "/api/aaaLogout.json"
        payload = {"aaaUser": {"attributes": {"name": self.connection.get_option("remote_user")}}}
        data = json.dumps(payload)
        try:
            response, response_data = self.connection.send(path, data, method=method)
        except Exception as exc_logout:
            msg = "Error on attempt to logout from APIC. {0}".format(exc_logout)
            raise ConnectionError(self._return_info(None, method, path, msg))
        self.connection._auth = None
        self._verify_response(response, method, path, response_data)

    def set_parameters(self):
        connection_parameters = {}
        for key in CONNECTION_KEYS:
            value = self.params.get(key) if self.params.get(key) is not None else self.connection.get_option(CONNECTION_MAP.get(key, key))
            self.connection.set_option(CONNECTION_MAP.get(key, key), value)
            if key == "timeout" and self.params.get(key) is not None:
                self.connection.set_option("persistent_connect_timeout", value + 30)

            connection_parameters[key] = value
            if self.connection_parameters and value != self.connection_parameters.get(key) and key in RESET_KEYS:
                self.connection._connected = False
                self.connection.queue_message("step", "Re-setting connection due to change in {0}".format(key))

            # if self.auth is not None or self.connection.get_option("session_key") is not None:
            #     self.connection._connected = True

        if self.connection_parameters != connection_parameters:
            self.connection_parameters = copy(connection_parameters)

    def set_hosts(self):
         if self.params.get("host") is not None:
            get_hosts = ast.literal_eval(self.params.get("host")) if "[" in self.params.get("host") else self.params.get("host").split(",") 
         else:
            self.get_first_item.append(re.sub(r"[[\]]", "", self.connection.get_option("host")).split(","))
            get_hosts = self.get_first_item[0]

         if self.provided_hosts is None:
            self.provided_hosts = get_hosts
            self.connection.queue_message(
                "step:", "Provided Hosts: {0}".format(self.provided_hosts)
            )
            self.backup_hosts = self.provided_hosts
            self.current_host = self.backup_hosts.pop(0)
         elif (len(self.backup_hosts) != 0 and self.current_host not in get_hosts) or self.connection_error_check == True:
            self.connection_error_check = False
            self.connection._connected = False
            self.connection.queue_message(
                "step:", "Provided hosts have changed: {0}".format(get_hosts)
            )
            self.backup_hosts = get_hosts
            self.current_host = self.backup_hosts.pop(0)
         self.connection.set_option("host", self.current_host)

    # One API call is made via each call to send_request from aci.py in module_utils
    # As long as a host is active in the list we make sure that the API call goes through
    def send_request(self, method, path, data):
        """This method handles all APIC REST API requests other than login"""

        self.set_parameters()
        self.set_hosts()

        try:
            response, response_data = self.connection.send(path, data, method=method)
            self.connection.queue_message(
                "step:", "Received response from {0} for {1} operation with HTTP: {2}".format(self.connection.get_option("host"), method, response.getcode())
            )
        except Exception as exc_response:
            if len(self.backup_hosts) == 0:
                return self._return_info("", method, re.match(r'^.*?\.json',self.connection._url+path).group(0), str(exc_response))
            self.connection.queue_message("step:", "Connection to {0} has failed in between operations with: {1}".format(self.connection.get_option("host"), exc_response))
            self.handle_connection_error(exc_response)
            self.connection.queue_message("step:", "Retrying request on {0}".format(self.connection.get_option("host")))
            # recurse through function for retrying the request
            return self.send_request(method, path, data)
        # return statement executed upon each successful response from the request function
        return self._verify_response(response, method, path, response_data)

    # Custom error handler
    def handle_connection_error(self, exception):
        if len(self.backup_hosts) == 0:
            self.connection_error_check = True
            raise ConnectionError(
                "No hosts left in cluster to continue operation!!! Error on final host {0}: {1}".format(self.connection.get_option("host"), exception)
            )
        self.current_host = self.backup_hosts.pop(0)
        self.connection.queue_message(
            "step:", "Switching host from {0} to {1}".format(self.connection.get_option("host"), self.current_host)
        )
        self.connection.set_option("host", self.current_host)
        # Login function is called until connection to a host is established or until all the hosts in the list are exhausted
        self.login(self.connection.get_option("remote_user"), self.connection.get_option("password"))

    # Built-in-function
    def handle_httperror(self, exc):
        self.connection.queue_message("step:", "Failed to receive response from {0}: {1}".format(self.connection.get_option("host"), exc))
        if exc.code == 401:
            return False
        elif exc.code == 403:
            self.connection._auth = None
            self.login(self.connection.get_option('remote_user'), self.connection.get_option('password'))
            return True
        return exc

    def _verify_response(self, response, method, path, response_data):
        """Process the return code and response object from APIC"""
        response_value = self._get_response_value(response_data)
        if path.find(".json") != -1:
            respond_data = self._response_to_json(response_value)
        else:
            respond_data = response_value
        response_code = response.getcode()
        path = re.match(r'^.*?\.json|^.*?\.xml', response.url).group(0)
        # Response check to remain consistent with fetch_url's response
        if str(response) == "HTTP Error 400: Bad Request":
            msg = "{0}".format(response)
        else:
            msg = "{0} ({1} bytes)".format(response.msg, len(response_value))
        return self._return_info(response_code, method, path, msg, respond_data)

    def _get_response_value(self, response_data):
        """Extract string data from response_data returned from APIC"""
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        """Convert response_text to json format"""
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except Exception:
            return "Invalid JSON response: {0}".format(response_text)

    def _return_info(self, response_code, method, path, msg, respond_data=None):
        """Format success/error data and return with consistent format"""
        info = {}
        info["status"] = response_code
        info["method"] = method
        info["url"] = path
        info["msg"] = msg
        if respond_data is not None:
            info["body"] = respond_data
        return info

    def cert_auth(self, path, method, payload=""):
        """Perform APIC signature-based authentication, not the expected SSL client certificate authentication."""

        headers = dict()

        if payload is None:
            payload = ""

        try:
            if HAS_CRYPTOGRAPHY:
                key = list(self.connection.get_option("session_key").values())[0].encode()
                sig_key = serialization.load_pem_private_key(
                    key,
                    password=None,
                    backend=default_backend(),
                )
            else:
                sig_key = load_privatekey(FILETYPE_PEM, list(self.connection.get_option("session_key").values())[0])
        except Exception:
            if os.path.exists(list(self.connection.get_option("session_key").values())[0]):
                try:
                    permission = "r"
                    if HAS_CRYPTOGRAPHY:
                        permission = "rb"
                    with open(list(self.connection.get_option("session_key").values())[0], permission) as fh:
                        private_key_content = fh.read()
                except Exception:
                    raise ConnectionError("Cannot open private key file {0}".format(list(self.connection.get_option("session_key").values())[0]))
                try:
                    if HAS_CRYPTOGRAPHY:
                        sig_key = serialization.load_pem_private_key(private_key_content, password=None, backend=default_backend())
                    else:
                        sig_key = load_privatekey(FILETYPE_PEM, private_key_content)
                except Exception:
                    raise ConnectionError("Cannot load private key file {0}".format(list(self.connection.get_option("session_key").values())[0]))
            else:
                raise ConnectionError(
                    "Provided private key {0} does not appear to be a private key.".format(list(self.connection.get_option("session_key").values())[0])
                )
        sig_request = method + path + payload
        if HAS_CRYPTOGRAPHY:
            sig_signature = sig_key.sign(sig_request.encode(), padding.PKCS1v15(), hashes.SHA256())
        else:
            sig_signature = sign(sig_key, sig_request, "sha256")
        sig_dn = "uni/userext/user-{0}/usercert-{1}".format(
            self.connection.get_option("remote_user"), list(self.connection.get_option("session_key").keys())[0]
        )
        headers["Cookie"] = (
            "APIC-Certificate-Algorithm=v1.0; "
            + "APIC-Certificate-DN=%s; " % sig_dn
            + "APIC-Certificate-Fingerprint=fingerprint; "
            + "APIC-Request-Signature=%s" % to_native(base64.b64encode(sig_signature))
        )
        return headers
