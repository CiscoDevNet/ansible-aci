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


class TestAciRestJsonFormat(ModuleTestCase):
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

    def test_json_format_path_without_extension(self):
        # json_format=True allows a path without a .json/.xml extension (e.g. APIC workflow APIs).
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="password",
                path="/api/workflows/v1/cluster/status",
                method="get",
                json_format=True,
            )
        )

        response_body = {"clusterHealth": {"status": "fully-fit"}}
        result = self.execute_module(response_body)

        # Non-MO responses do not have an "imdata" key, the raw body is returned as-is.
        self.assertEqual(result["imdata"], response_body)

    def test_json_format_post_does_not_add_rsp_subtree(self):
        # rsp-subtree=modified is an ACI MO-specific query parameter and must not be appended
        # to non-MO json_format paths (e.g. APIC workflow APIs), even for POST/DELETE methods.
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="password",
                path="/api/workflows/v1/controller/verify",
                method="post",
                json_format=True,
                output_level="debug",
                content=dict(address="10.0.0.1", username="admin", password="bogus", addressType="cimc", controllerType="physical"),
            )
        )

        response_body = {"status": "failed"}
        result = self.execute_module(response_body)

        self.assertNotIn("rsp-subtree", result["url"])

    def test_json_extension_post_still_adds_rsp_subtree(self):
        # Baseline/regression check: standard MO POST requests are unaffected by the json_format change.
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

    def test_json_format_path_with_dot_in_query_string_is_still_detected(self):
        # A "." in the query string (not the path itself) must not prevent a non-MO json_format
        # path from being recognized as JSON.
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="secret123",
                path="/api/workflows/v1/cluster/status?name=test.name",
                method="get",
                json_format=True,
            )
        )

        response_body = {"clusterHealth": {"status": "fully-fit"}}
        result = self.execute_module(response_body)

        self.assertEqual(result["imdata"], response_body)

    def test_json_format_path_with_dot_in_a_non_final_path_segment(self):
        # A "." earlier in the path (e.g. an API version segment) but not in the final segment
        # must still be recognized as a non-MO json_format path.
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="secret123",
                path="/api/workflows/v1.0/cluster/status",
                method="get",
                json_format=True,
            )
        )

        response_body = {"clusterHealth": {"status": "fully-fit"}}
        result = self.execute_module(response_body)

        self.assertEqual(result["imdata"], response_body)

    def test_json_format_path_with_dot_in_final_path_segment(self):
        # A "." in the final path segment that is not a .json/.xml extension (e.g. a domain-like
        # segment) must still be recognized as a non-MO json_format path, not rejected.
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="password",
                path="/api/workflows/v1/cluster/test.name",
                method="get",
                json_format=True,
            )
        )

        response_body = {"clusterHealth": {"status": "fully-fit"}}
        result = self.execute_module(response_body)

        self.assertEqual(result["imdata"], response_body)

    def test_json_extension_path_returns_imdata(self):
        # Baseline/regression check: standard MO responses are unaffected by the json_format change.
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

    def test_path_without_extension_and_without_json_format_fails(self):
        # Without json_format, a path missing .json/.xml is rejected with a warning and an error.
        set_module_args(
            dict(
                host="apic",
                username="admin",
                password="password",
                path="/api/workflows/v1/cluster/status",
                method="get",
            )
        )

        with patch.object(ACIModule, "login", return_value=None):
            with self.assertRaises(AnsibleFailJson) as result:
                aci_rest.main()

        self.assertEqual(result.exception.args[0]["msg"], "Failed to find REST API payload type (neither .xml nor .json).")


class TestAddAnnotation(unittest.TestCase):
    """add_annotation() is expected to only annotate standard ACI Managed Object (MO) payload
    nodes (identified by the presence of an "attributes" key) and to leave non-MO JSON payloads
    (e.g. those used with json_format) untouched."""

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
        # Non-MO JSON payloads (e.g. json_format paths without a .json/.xml extension) do not
        # follow the MO "attributes"/"children" structure and must not be modified or raise errors.
        payload = {"spec": {"steps": [{"name": "step1"}]}}
        aci_rest.add_annotation("orchestrator:ansible", payload)
        self.assertEqual(payload, {"spec": {"steps": [{"name": "step1"}]}})

    def test_add_annotation_without_annotation_param_does_nothing(self):
        payload = {"fvTenant": {"attributes": {"name": "Sales"}}}
        aci_rest.add_annotation(None, payload)
        self.assertNotIn("annotation", payload["fvTenant"]["attributes"])
