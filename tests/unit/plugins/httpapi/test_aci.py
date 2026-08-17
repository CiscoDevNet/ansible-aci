# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Samita Bhattacharjee (@samiib) <samitab@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.aci.tests.unit.compat import unittest
from ansible_collections.cisco.aci.plugins.httpapi.aci import HttpApi


class AltHttpApi(HttpApi):
    """Bypass HttpApiBase.__init__ (which requires a live connection object) so validate_url() can be unit tested in isolation."""

    def __init__(self, port=None):
        self.connection_parameters = dict(port=port)


class TestValidateUrl(unittest.TestCase):
    def test_json_extension_with_port(self):
        httpapi = AltHttpApi(port=443)
        url = "https://10.0.0.1:443/api/mo/uni.json?rsp-subtree=modified"
        self.assertEqual(httpapi.validate_url(url), "https://10.0.0.1:443/api/mo/uni.json")

    def test_json_extension_without_port(self):
        httpapi = AltHttpApi(port=None)
        url = "https://10.0.0.1:443/api/mo/uni.json?rsp-subtree=modified"
        self.assertEqual(httpapi.validate_url(url), "https://10.0.0.1/api/mo/uni.json")

    def test_xml_extension_with_port(self):
        httpapi = AltHttpApi(port=443)
        url = "https://10.0.0.1:443/api/mo/uni.xml?rsp-subtree=modified"
        self.assertEqual(httpapi.validate_url(url), "https://10.0.0.1:443/api/mo/uni.xml")

    def test_xml_extension_without_port(self):
        httpapi = AltHttpApi(port=None)
        url = "https://10.0.0.1:443/api/mo/uni.xml?rsp-subtree=modified"
        self.assertEqual(httpapi.validate_url(url), "https://10.0.0.1/api/mo/uni.xml")

    def test_no_extension_json_format_with_port(self):
        # e.g. json_format paths such as APIC workflow APIs that do not use a .json or .xml extension.
        httpapi = AltHttpApi(port=443)
        url = "https://10.0.0.1:443/api/workflows/v1/cluster/status?rsp-subtree=modified"
        self.assertEqual(httpapi.validate_url(url), "https://10.0.0.1:443/api/workflows/v1/cluster/status")

    def test_no_extension_json_format_without_port(self):
        httpapi = AltHttpApi(port=None)
        url = "https://10.0.0.1:443/api/workflows/v1/cluster/status?rsp-subtree=modified"
        self.assertEqual(httpapi.validate_url(url), "https://10.0.0.1/api/workflows/v1/cluster/status")

    def test_no_extension_json_format_without_query_string(self):
        httpapi = AltHttpApi(port=443)
        url = "https://10.0.0.1:443/api/workflows/v1/cluster/status"
        self.assertEqual(httpapi.validate_url(url), "https://10.0.0.1:443/api/workflows/v1/cluster/status")
