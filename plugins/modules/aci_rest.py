#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2020, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_rest
short_description: Direct access to the Cisco APIC REST API
description:
- Enables the management of the Cisco ACI fabric through direct access to the Cisco APIC REST API.
- Thanks to the idempotent nature of the APIC, this module is idempotent and reports changes.
requirements:
- lxml (when using XML payload)
- xmljson >= 0.1.8 (when using XML payload)
- python 2.7+ (when using xmljson)
options:
  method:
    description:
    - The HTTP method of the request.
    - Using C(delete) is typically used for deleting objects.
    - Using C(get) is typically used for querying objects.
    - Using C(post) is typically used for modifying objects.
    type: str
    choices: [ delete, get, post ]
    default: get
    aliases: [ action ]
  path:
    description:
    - URI being used to execute API calls.
    - Must end in C(.xml) or C(.json).
    type: str
    required: yes
    aliases: [ uri ]
  content:
    description:
    - When used instead of C(src), sets the payload of the API request directly.
    - This may be convenient to template simple requests.
    - For anything complex use the C(template) lookup plugin (see examples)
      or the M(template) module with parameter C(src).
    type: raw
  src:
    description:
    - Name of the absolute path of the filename that includes the body
      of the HTTP request being sent to the ACI fabric.
    - If you require a templated payload, use the C(content) parameter
      together with the C(template) lookup plugin, or use M(template).
    type: path
    aliases: [ config_file ]
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

notes:
- Certain payloads are known not to be idempotent, so be careful when constructing payloads,
  e.g. using C(status="created") will cause idempotency issues, use C(status="modified") instead.
  More information in :ref:`the ACI documentation <aci_guide_known_issues>`.
- Certain payloads (and used paths) are known to report no changes happened when changes did happen.
  This is a known APIC problem and has been reported to the vendor. A workaround for this issue exists.
  More information in :ref:`the ACI documentation <aci_guide_known_issues>`.
- XML payloads require the C(lxml) and C(xmljson) python libraries. For JSON payloads nothing special is needed.
- If you do not have any attributes, it may be necessary to add the "attributes" key with an empty dictionnary "{}" for value
  as the APIC does expect the entry to precede any children.
seealso:
- module: cisco.aci.aci_tenant
- name: Cisco APIC REST API Configuration Guide
  description: More information about the APIC REST API.
  link: http://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/2-x/rest_cfg/2_1_x/b_Cisco_APIC_REST_API_Configuration_Guide.html
author:
- Dag Wieers (@dagwieers)
- Cindy Zhao (@cizhao)
"""

EXAMPLES = r"""
- name: Add a tenant using certificate authentication
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/admin.key
    method: post
    path: /api/mo/uni.xml
    src: /home/cisco/ansible/aci/configs/aci_config.xml
  delegate_to: localhost

- name: Add a tenant from a templated payload file from templates/
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/admin.key
    method: post
    path: /api/mo/uni.xml
    content: "{{ lookup('template', 'aci/tenant.xml.j2') }}"
  delegate_to: localhost

- name: Add a tenant using inline YAML
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/admin.key
    validate_certs: no
    path: /api/mo/uni.json
    method: post
    content:
      fvTenant:
        attributes:
          name: Sales
          descr: Sales department
  delegate_to: localhost

- name: Add a tenant using a JSON string
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/admin.key
    validate_certs: no
    path: /api/mo/uni.json
    method: post
    content:
      {
        "fvTenant": {
          "attributes": {
            "name": "Sales",
            "descr": "Sales department"
          }
        }
      }
  delegate_to: localhost

- name: Add a tenant using an XML string
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/{{ aci_username }}.key
    validate_certs: no
    path: /api/mo/uni.xml
    method: post
    content: '<fvTenant name="Sales" descr="Sales departement"/>'
  delegate_to: localhost

- name: Get tenants using password authentication
  cisco.aci.aci_rest:
    host: apic
    username: admin
    password: SomeSecretPassword
    method: get
    path: /api/node/class/fvTenant.json
  delegate_to: localhost
  register: query_result

- name: Configure contracts
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/admin.key
    method: post
    path: /api/mo/uni.xml
    src: /home/cisco/ansible/aci/configs/contract_config.xml
  delegate_to: localhost

- name: Register leaves and spines
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/admin.key
    validate_certs: no
    method: post
    path: /api/mo/uni/controller/nodeidentpol.xml
    content:
      <fabricNodeIdentPol>
        <fabricNodeIdentP name="{{ item.name }}" nodeId="{{ item.nodeid }}" status="{{ item.status }}" serial="{{ item.serial }}"/>
      </fabricNodeIdentPol>
  with_items:
  - '{{ apic_leavesspines }}'
  delegate_to: localhost

- name: Wait for all controllers to become ready
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/admin.key
    validate_certs: no
    path: /api/node/class/topSystem.json?query-target-filter=eq(topSystem.role,"controller")
  register: apics
  until: "'totalCount' in apics and apics.totalCount|int >= groups['apic']|count"
  retries: 120
  delay: 30
  delegate_to: localhost
  run_once: yes
"""

RETURN = r"""
error_code:
  description: The REST ACI return code, useful for troubleshooting on failure
  returned: always
  type: int
  sample: 122
error_text:
  description: The REST ACI descriptive text, useful for troubleshooting on failure
  returned: always
  type: str
  sample: unknown managed object class foo
imdata:
  description: Converted output returned by the APIC REST (register this for post-processing)
  returned: always
  type: str
  sample: [{"error": {"attributes": {"code": "122", "text": "unknown managed object class foo"}}}]
payload:
  description: The (templated) payload send to the APIC REST API (xml or json)
  returned: always
  type: str
  sample: '<foo bar="boo"/>'
raw:
  description: The raw output returned by the APIC REST API (xml or json)
  returned: parse error
  type: str
  sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class foo"/></imdata>'
response:
  description: HTTP response string
  returned: always
  type: str
  sample: 'HTTP Error 400: Bad Request'
status:
  description: HTTP status code
  returned: always
  type: int
  sample: 400
totalCount:
  description: Number of items in the imdata array
  returned: always
  type: str
  sample: '0'
url:
  description: URL used for APIC REST call
  returned: success
  type: str
  sample: https://1.2.3.4/api/mo/uni/tn-[Dag].json?rsp-subtree=modified
"""

import json
import os

try:
    from ansible.module_utils.six.moves.urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

    HAS_URLPARSE = True
except Exception:
    HAS_URLPARSE = False

# Optional, only used for XML payload
try:
    from lxml import etree  # noqa

    HAS_LXML_ETREE = True
except ImportError:
    HAS_LXML_ETREE = False

# Optional, only used for XML payload
try:
    from xmljson import cobra  # noqa

    HAS_XMLJSON_COBRA = True
except ImportError:
    HAS_XMLJSON_COBRA = False

# Optional, only used for YAML validation
try:
    import yaml

    HAS_YAML = True
except Exception:
    HAS_YAML = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible.module_utils.urls import fetch_url
from ansible.module_utils._text import to_text


def update_qsl(url, params):
    """Add or update a URL query string"""

    if HAS_URLPARSE:
        url_parts = list(urlparse(url))
        query = dict(parse_qsl(url_parts[4]))
        query.update(params)
        url_parts[4] = urlencode(query)
        return urlunparse(url_parts)
    elif "?" in url:
        return url + "&" + "&".join(["%s=%s" % (k, v) for k, v in params.items()])
    else:
        return url + "?" + "&".join(["%s=%s" % (k, v) for k, v in params.items()])


class ACIRESTModule(ACIModule):
    def changed(self, d):
        """Check ACI response for changes"""

        if isinstance(d, dict):
            for k, v in d.items():
                if k == "status" and v in ("created", "modified", "deleted"):
                    return True
                elif self.changed(v) is True:
                    return True
        elif isinstance(d, list):
            for i in d:
                if self.changed(i) is True:
                    return True

        return False

    def response_type(self, rawoutput, rest_type="xml"):
        """Handle APIC response output"""

        if rest_type == "json":
            self.response_json(rawoutput)
        else:
            self.response_xml(rawoutput)

        # Use APICs built-in idempotency
        if HAS_URLPARSE:
            self.result["changed"] = self.changed(self.imdata)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        path=dict(type="str", required=True, aliases=["uri"]),
        method=dict(type="str", default="get", choices=["delete", "get", "post"], aliases=["action"]),
        src=dict(type="path", aliases=["config_file"]),
        content=dict(type="raw"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[["content", "src"]],
    )

    content = module.params.get("content")
    path = module.params.get("path")
    src = module.params.get("src")

    # Report missing file
    file_exists = False
    if src:
        if os.path.isfile(src):
            file_exists = True
        else:
            module.fail_json(msg="Cannot find/access src '%s'" % src)

    # Find request type
    if path.find(".xml") != -1:
        rest_type = "xml"
        if not HAS_LXML_ETREE:
            module.fail_json(msg="The lxml python library is missing, or lacks etree support.")
        if not HAS_XMLJSON_COBRA:
            module.fail_json(msg="The xmljson python library is missing, or lacks cobra support.")
    elif path.find(".json") != -1:
        rest_type = "json"
    else:
        module.fail_json(msg="Failed to find REST API payload type (neither .xml nor .json).")

    aci = ACIRESTModule(module)
    aci.result["status"] = -1  # Ensure we always return a status

    # We include the payload as it may be templated
    payload = content
    if file_exists:
        with open(src, "r") as config_object:
            # TODO: Would be nice to template this, requires action-plugin
            payload = config_object.read()
            payload_output_file = json.loads(payload)

    # Validate payload
    if rest_type == "json":
        if content and isinstance(content, dict):
            # Validate inline YAML/JSON
            payload = json.dumps(payload)
            payload_output_file = json.loads(payload)
        elif payload and isinstance(payload, str) and HAS_YAML:
            try:
                # Validate YAML/JSON string
                payload = json.dumps(yaml.safe_load(payload))
                payload_output_file = json.loads(payload)
            except Exception as e:
                module.fail_json(msg="Failed to parse provided JSON/YAML payload: %s" % to_text(e), exception=to_text(e), payload=payload)
    elif rest_type == "xml" and HAS_LXML_ETREE:
        if content and isinstance(content, dict) and HAS_XMLJSON_COBRA:
            # Validate inline YAML/JSON
            payload = etree.tostring(cobra.etree(payload)[0])
        elif payload and isinstance(payload, str):
            try:
                # Validate XML string
                payload = etree.tostring(etree.fromstring(payload))
            except Exception as e:
                module.fail_json(msg="Failed to parse provided XML payload: %s" % to_text(e), payload=payload)

    # Perform actual request using auth cookie (Same as aci.request(), but also supports XML)
    if "port" in aci.params and aci.params.get("port") is not None:
        aci.url = "%(protocol)s://%(host)s:%(port)s/" % aci.params + path.lstrip("/")
    else:
        aci.url = "%(protocol)s://%(host)s/" % aci.params + path.lstrip("/")
    if aci.params.get("method") != "get":
        path += "?rsp-subtree=modified"
        aci.url = update_qsl(aci.url, {"rsp-subtree": "modified"})

    # Sign and encode request as to APIC's wishes
    if aci.params.get("private_key") is not None:
        aci.cert_auth(path=path, payload=payload)

    aci.method = aci.params.get("method").upper()

    # Perform request
    resp, info = fetch_url(
        module, aci.url, data=payload, headers=aci.headers, method=aci.method, timeout=aci.params.get("timeout"), use_proxy=aci.params.get("use_proxy")
    )

    aci.response = info.get("msg")
    aci.status = info.get("status")

    # Report failure
    if info.get("status") != 200:
        try:
            # APIC error
            aci.response_type(info.get("body"), rest_type)
            aci.fail_json(msg="APIC Error %(code)s: %(text)s" % aci.error)
        except KeyError:
            # Connection error
            aci.fail_json(msg="Connection failed for %(url)s. %(msg)s" % info)

    aci.response_type(resp.read(), rest_type)

    aci.result["imdata"] = aci.imdata
    aci.result["totalCount"] = aci.totalCount

    if aci.params.get("method") != "get":
        output_path = aci.params.get("output_path")
        if output_path is not None:
            with open(output_path, "a") as output_file:
                json.dump([payload_output_file], output_file)

    # Report success
    aci.exit_json(**aci.result)


if __name__ == "__main__":
    main()
