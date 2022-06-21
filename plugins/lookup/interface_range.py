#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = """
    name: interface_range
    short_description: interfaces from range
    description:
      - this lookup returns interfaces from a range given to it
    notes:
      - add document
    options:
      _terms:
        description: comma separated strings of interface ranges
        required: True
"""

EXAMPLES = """
- name: "loop through range of interfaces"
  ansible.builtin.debug:
    msg: "{{ item }}"
  with_items: "{{ query('cisco.aci.interface_range', '1/1-4,1/20-25,1/31-32,2/10-15,2/11-12,2/13-13', '1/5-9,4/8-10', '5/0-2') }}"
"""

RETURN = """
  _list:
    description: list of interfaces
    type: list
    elements: str
"""

import re

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase


class LookupModule(LookupBase):

    def run(self, terms, **kwargs):

        int_range = ','.join(terms).replace(" ", "")
        # Regex could be made more specific to match max amount of slots/ports supported in nexus devices
        val_regex = "([0-9]/[0-9]{1,2}-[0-9]{1,2})|(^([0-9]/[0-9]{1,2}-[0-9]{1,2},)+([0-9]/[0-9]{1,2}-[0-9]{1,2})$)"
        interfaces = []

        if re.fullmatch(val_regex, int_range):

            for r in [(r.split("/")[0], int(r.split("/")[1].split("-")[0]), int(r.split("/")[1].split("-")[1])) for r in int_range.split(",")]:
                if r[2] >= r[1]:
                    for x in range(r[1], r[2] + 1):
                        interfaces.append(f"{r[0]}/{x}")
                else:
                    raise AnsibleError("INVALID RANGE INPUT: End '{0}/{1}-{2}' is smaller than begin of interface range.".format(r[0], r[1], r[2]))
        else:
            raise AnsibleError("INVALID RANGE INPUT: Range not matching pattern '1/20-21' or '1/20-21,1/24-27' for interface ranges.")

        # Sorted functionality for visual aid only, will result in 1/25, 1/3, 1/31
        # If full sort is needed leverage natsort package (https://github.com/SethMMorton/natsort)
        return sorted(set(interfaces))
