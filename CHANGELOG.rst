==========================================
Cisco ACI Ansible Collection Release Notes
==========================================

.. contents:: Topics


v1.0.0
======

Release Summary
---------------

This is the first official release of the ``cisco.aci`` collection on 2020-08-18.
This changelog describes all changes made to the modules and plugins included in this collection since Ansible 2.9.0.


Minor Changes
-------------

- Add Fex capability to aci_interface_policy_leaf_profile, aci_access_port_to_interface_policy_leaf_profile and aci_access_port_block_to_access_port
- Add LICENSE file
- Add aci_epg_to_contract_master module
- Add annotation attribute to aci.py and to doc fragment.
- Add annotation to every payload and add test case for annotation.
- Add changelog
- Add collection prefix to all integration tests
- Add galaxy.yml file for collection listing
- Add github action CI pipeline
- Add module and test file for aci_bd_dhcp_label
- Add modules and test files for aci_cloud_ctx_profile, aci_cloud_cidr, aci_cloud_subnet and aci_cloud_zone
- Add modules and test files for aci_l2out, aci_l2out_extepg and aci_l3out_extepg_to_contract
- Add names to documentation examples for modules from community.network
- Add preferred group support to aci_vrf
- Add support for Azure on all cloud modules
- Add support for output_path to allow dump of REST API objects
- Add support for owner_key and owner_tag for all modules and add test case for it.
- Add vpn gateway dedicated module and remove vpn_gateway from cloud_ctx_profile module
- Fix M() and module to use FQCN
- Initial commit based on the collection migration available at "ansible-collection-migration/cisco.aci" which contains the ACI module from Ansible Core
- Move aci.py to base of module_utils and fix references
- Move test file to root of tests/unit/module_utils
- Update Ansible version in CI and add 2.10.0 to sanity in CI.
- Update Readme with supported versions
- Update to test files to make the tests work on both 3.2 and 4.2.

Bugfixes
--------

- Fix sanity issues to support 2.10.0
- Fix some doc issues for a few modules
- Fix some formatting issues (flake8) in unit tests.
- Fixing integration tests and sanity. Tested on ACI 4.2(3l).
