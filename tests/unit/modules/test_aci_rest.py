# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Samita Bhattacharjee (@samiib) <samitab@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json

from ansible_collections.cisco.aci.plugins.modules import aci_rest
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule
from ansible_collections.cisco.aci.tests.unit.compat import unittest
from ansible_collections.cisco.aci.tests.unit.compat.mock import MagicMock, patch

from .utils import AnsibleExitJson, AnsibleFailJson, ModuleTestCase, set_module_args


class TestAciRestPathDetection(ModuleTestCase):
    """Demonstrates mocking the ACI login and HTTP layers so aci_rest.main() can be
    unit tested end-to-end without a real APIC connection."""

    def execute_module(self, response_body, status=200):
        """Run aci_rest.main() with login and the HTTP call mocked out, returning the module result."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(response_body).encode()
        info = dict(status=status, body=json.dumps(response_body).encode(), msg="OK (200)", url="https://apic")

        # ACIModule.login() would otherwise perform a real aaaLogin POST request.
        with patch.object(ACIModule, "login", return_value=None):
            # fetch_url is used by ACIModule.api_call() to perform the actual REST request.
            with patch("ansible_collections.cisco.aci.plugins.module_utils.aci.fetch_url", return_value=(mock_resp, info)):
                with self.assertRaises(AnsibleExitJson) as result:
                    aci_rest.main()
        return result.exception.args[0]

    def test_non_mo_path_without_extension(self):
        # A path without a .json/.xml extension (e.g. APIC workflow APIs) is auto-detected as
        # a non-MO JSON API since it does not match the MO/Class path pattern.
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="password",
                path="/api/workflows/v1/cluster/status",
                method="get",
            )
        )

        response_body = {"clusterHealth": {"status": "fully-fit"}}
        result = self.execute_module(response_body)

        # Non-MO responses do not have an "imdata" key, the raw body is returned as-is.
        self.assertEqual(result["data"], response_body)

    def test_non_mo_post_does_not_add_rsp_subtree(self):
        # rsp-subtree=modified is an ACI MO-specific query parameter and must not be appended
        # to non-MO paths (e.g. APIC workflow APIs), even for POST/DELETE methods.
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="password",
                path="/api/workflows/v1/controller/verify",
                method="post",
                output_level="debug",
                content=dict(address="10.0.0.1", username="admin", password="bogus", addressType="cimc", controllerType="physical"),
            )
        )

        response_body = {"status": "failed"}
        result = self.execute_module(response_body)

        self.assertNotIn("rsp-subtree", result["url"])

    def test_json_extension_post_still_adds_rsp_subtree(self):
        # Baseline/regression check: standard MO POST requests are unaffected by the auto-detection change.
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="password",
                path="/api/mo/uni/tn-ansible_test.json",
                method="post",
                output_level="debug",
                content=dict(fvTenant=dict(attributes=dict(name="ansible_test"))),
            )
        )

        response_body = {"totalCount": "1", "imdata": [{"fvTenant": {"attributes": {"name": "ansible_test"}}}]}
        result = self.execute_module(response_body)

        self.assertIn("rsp-subtree=modified", result["url"])

    def test_json_extension_post_without_leading_slash_still_adds_rsp_subtree(self):
        # A standard MO path missing its leading "/" (e.g. "api/mo/..." instead of "/api/mo/...")
        # must still be recognized as a standard ACI MO/Class API path.
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="password",
                path="api/mo/uni/tn-ansible_test.json",
                method="post",
                output_level="debug",
                content=dict(fvTenant=dict(attributes=dict(name="ansible_test"))),
            )
        )

        response_body = {"totalCount": "1", "imdata": [{"fvTenant": {"attributes": {"name": "ansible_test"}}}]}
        result = self.execute_module(response_body)

        self.assertIn("rsp-subtree=modified", result["url"])
        self.assertEqual(result["imdata"], response_body["imdata"])

    def test_json_path_with_xml_in_query_string_is_not_misdetected_as_xml(self):
        # A query string value containing ".xml" must not cause the module to mistakenly treat
        # a .json path as XML (the extension check must only look at the actual path component).
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="secret123",
                path='/api/class/topSystem.json?query-target-filter=eq(topSystem.name,"leaf-101.xml")',
                method="get",
            )
        )

        response_body = {"totalCount": "1", "imdata": [{"topSystem": {"attributes": {"name": "leaf-101"}}}]}
        result = self.execute_module(response_body)

        self.assertEqual(result["imdata"], response_body["imdata"])

    def test_non_mo_path_with_dot_in_query_string_is_still_detected(self):
        # A "." in the query string (not the path itself) must not prevent a non-MO path
        # from being recognized as JSON.
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="secret123",
                path="/api/workflows/v1/cluster/status?name=test.name",
                method="get",
            )
        )

        response_body = {"clusterHealth": {"status": "fully-fit"}}
        result = self.execute_module(response_body)

        self.assertEqual(result["data"], response_body)

    def test_non_mo_path_with_dot_in_a_non_final_path_segment(self):
        # A "." earlier in the path (e.g. an API version segment) but not in the final segment
        # must still be recognized as a non-MO path.
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="secret123",
                path="/api/workflows/v1.0/cluster/status",
                method="get",
            )
        )

        response_body = {"clusterHealth": {"status": "fully-fit"}}
        result = self.execute_module(response_body)

        self.assertEqual(result["data"], response_body)

    def test_non_mo_path_with_dot_in_final_path_segment(self):
        # A "." in the final path segment that is not a .json/.xml extension (e.g. a domain-like
        # segment) must still be recognized as a non-MO path, not rejected.
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="password",
                path="/api/workflows/v1/cluster/test.name",
                method="get",
            )
        )

        response_body = {"clusterHealth": {"status": "fully-fit"}}
        result = self.execute_module(response_body)

        self.assertEqual(result["data"], response_body)

    def test_json_extension_path_returns_imdata(self):
        # Baseline/regression check: standard MO responses are unaffected by the auto-detection change.
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="password",
                path="/api/class/topSystem.json",
                method="get",
            )
        )

        response_body = {"totalCount": "1", "imdata": [{"topSystem": {"attributes": {"name": "leaf-101"}}}]}
        result = self.execute_module(response_body)

        self.assertEqual(result["imdata"], response_body["imdata"])
        self.assertEqual(result["totalCount"], 1)

    def test_standard_api_path_without_extension_fails(self):
        # A standard ACI MO/Class API path missing .json/.xml is rejected with an error.
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="password",
                path="/api/mo/uni/tn-ansible_test",
                method="get",
            )
        )

        with patch.object(ACIModule, "login", return_value=None):
            with self.assertRaises(AnsibleFailJson) as result:
                aci_rest.main()

        self.assertEqual(result.exception.args[0]["msg"], "Failed to find REST API payload type (neither .xml nor .json).")

    def test_non_mo_prefix_path_with_json_extension_returns_data(self):
        # A path outside the MO/Class path pattern (e.g. /connector/Systems.json) is treated as a
        # generic JSON API, even though it ends in .json. Its response is returned under "data"
        # instead of "imdata"/"totalCount". See https://github.com/CiscoDevNet/ansible-aci/issues/685
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="password",
                path="/connector/Systems.json",
                method="post",
                output_level="debug",
                content=dict(AdminState=False),
            )
        )

        response_body = [{"AdminState": False}]
        result = self.execute_module(response_body)

        self.assertEqual(result["data"], response_body)
        self.assertNotIn("rsp-subtree", result["url"])


class TestAddAnnotation(unittest.TestCase):
    """add_annotation() is expected to only annotate standard ACI Managed Object (MO) payload
    nodes (identified by the presence of an "attributes" key) and to leave non-MO JSON payloads
    (e.g. generic JSON APIs) untouched."""

    def test_add_annotation_to_mo_payload(self):
        payload = {"fvTenant": {"attributes": {"name": "Sales"}}}
        aci_rest.add_annotation("orchestrator:ansible", payload)
        self.assertEqual(payload["fvTenant"]["attributes"]["annotation"], "orchestrator:ansible")

    def test_add_annotation_recurses_into_children(self):
        payload = {
            "fvTenant": {
                "attributes": {"name": "Sales"},
                "children": [{"fvAp": {"attributes": {"name": "AP1"}}}],
            }
        }
        aci_rest.add_annotation("orchestrator:ansible", payload)
        self.assertEqual(payload["fvTenant"]["attributes"]["annotation"], "orchestrator:ansible")
        self.assertEqual(payload["fvTenant"]["children"][0]["fvAp"]["attributes"]["annotation"], "orchestrator:ansible")

    def test_add_annotation_does_not_overwrite_existing_annotation(self):
        payload = {"fvTenant": {"attributes": {"name": "Sales", "annotation": "custom:preexisting"}}}
        aci_rest.add_annotation("orchestrator:ansible", payload)
        self.assertEqual(payload["fvTenant"]["attributes"]["annotation"], "custom:preexisting")

    def test_add_annotation_skips_annotation_unsupported_classes(self):
        # "fvACont" is part of ANNOTATION_UNSUPPORTED and must never be annotated, even though it has attributes.
        payload = {"fvACont": {"attributes": {"name": "test"}}}
        aci_rest.add_annotation("orchestrator:ansible", payload)
        self.assertNotIn("annotation", payload["fvACont"]["attributes"])

    def test_add_annotation_skips_non_mo_payload_without_attributes(self):
        # Non-MO JSON payloads (e.g. generic JSON API paths without a .json/.xml extension) do not
        # follow the MO "attributes"/"children" structure and must not be modified or raise errors.
        payload = {"spec": {"steps": [{"name": "step1"}]}}
        aci_rest.add_annotation("orchestrator:ansible", payload)
        self.assertEqual(payload, {"spec": {"steps": [{"name": "step1"}]}})

    def test_add_annotation_without_annotation_param_does_nothing(self):
        payload = {"fvTenant": {"attributes": {"name": "Sales"}}}
        aci_rest.add_annotation(None, payload)
        self.assertNotIn("annotation", payload["fvTenant"]["attributes"])
