# Copyright (c) 2023 Cisco and/or its affiliates.
# Copyright: (c) 2023, Shreyas Srish (@shrsr) <ssrish@cisco.com>

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ipaddress import ip_network
import random

RANGE_IPV4 = list(ip_network("192.0.2.0/24").hosts()) + list(ip_network("198.51.100.0/24").hosts()) + list(ip_network("203.0.113.0/24").hosts())


class FilterModule(object):
    def filters(self):
        return {
            "generate_random_ips": self.generate_random_ips,
        }

    def generate_random_ips(self, given_ip, insert_given_ip_at, number_of_ips):
        ips = ""
        for i in range(number_of_ips):
            if i == insert_given_ip_at - 1:
                ips += given_ip
            else:
                ips += str((random.choice(RANGE_IPV4)))
            ips += ","
        return ips.rstrip(",")
