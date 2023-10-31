# Copyright: (c) 2017, Ramses Smeyers <rsmeyers@cisco.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
    name: aci_listify
    short_description: Flattens the nested dictionaries representing the ACI model data.
    description:
      - This filter flattens and transforms the input data into a list.
      - See the Examples section below.
    options:
      data:
        description: This option represents the ACI model data which is a list of dictionaries or a dictionary with any level of nesting data.
        type: raw
        required: True
      keys:
        description: Comma separated keys of type string denoting the ACI objects.
        required: True
"""

EXAMPLES = r"""
- name: Set vars
  ansible.builtin.set_fact:
    data:
      tenant:
      - name: ansible_test
        description: Created using listify
        app:
        - name: app_test
          epg:
          - name: web
            bd: web_bd
          - name: app
            bd: app_bd
        bd:
        - name: bd_test
          subnet:
          - name: 10.10.10.1
            mask: 24
            scope: private
          vrf: vrf_test
        - name: bd_test2
          subnet:
          - name: 20.20.20.1
            mask: 24
            scope: public
          vrf: vrf_test
        vrf:
        - name: vrf_test

- name: Create tenants
  cisco.aci.aci_tenant:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: '{{ item.tenant_name }}'
    description: '{{ item.tenant_description }}'
  with_items: '{{ data|cisco.aci.aci_listify("tenant") }}'

- name: Create VRFs
  cisco.aci.aci_vrf:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: '{{ item.tenant_name }}'
    vrf_name: '{{ item.tenant_vrf_name }}'
  with_items: '{{ data|cisco.aci.aci_listify("tenant","vrf") }}'

- name: Create BDs
  cisco.aci.aci_bd:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: '{{ item.tenant_name }}'
    vrf: '{{ item.tenant_bd_vrf }}'
    bd: '{{ item.tenant_bd_name }}'
    enable_routing: yes
  with_items: '{{ data|cisco.aci.aci_listify("tenant","bd") }}'

- name: Create BD subnets
  cisco.aci.aci_bd_subnet:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: '{{ item.tenant_name }}'
    bd: '{{ item.tenant_bd_name }}'
    gateway: '{{ item.tenant_bd_subnet_name }}'
    mask: '{{ item.tenant_bd_subnet_mask }}'
    scope: '{{ item.tenant_bd_subnet_scope }}'
  with_items: '{{ data|cisco.aci.aci_listify("tenant","bd","subnet") }}'

- name: Create APs
  cisco.aci.aci_ap:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: '{{ item.tenant_name }}'
    app_profile: '{{ item.tenant_app_name }}'
  with_items: '{{ data|cisco.aci.aci_listify("tenant","app") }}'

- name: Create EPGs
  cisco.aci.aci_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: '{{ item.tenant_name }}'
    app_profile: '{{ item.tenant_app_name }}'
    epg: '{{ item.tenant_app_epg_name }}'
    bd: '{{ item.tenant_app_epg_bd }}'
  with_items: '{{ data|cisco.aci.aci_listify("tenant","app","epg") }}'
"""


def listify(d, *keys):
    return listify_worker(d, keys, 0, [], {}, "")


def listify_worker(d, keys, depth, result, cache, prefix):
    prefix += keys[depth] + "_"

    if keys[depth] in d:
        for item in d[keys[depth]]:
            cache_work = cache.copy()
            if isinstance(item, dict):
                for k, v in item.items():
                    if not isinstance(v, dict) and not isinstance(v, list):
                        cache_key = prefix + k
                        cache_value = v
                        cache_work[cache_key] = cache_value

                if len(keys) - 1 == depth:
                    result.append(cache_work)
                else:
                    for k, v in item.items():
                        if k == keys[depth + 1]:
                            if isinstance(v, dict) or isinstance(v, list):
                                result = listify_worker({k: v}, keys, depth + 1, result, cache_work, prefix)
    return result


class FilterModule(object):
    """Ansible core jinja2 filters"""

    def filters(self):
        return {
            "aci_listify": listify,
        }
