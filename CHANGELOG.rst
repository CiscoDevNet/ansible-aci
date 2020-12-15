==========================================
Cisco ACI Ansible Collection Release Notes
==========================================

.. contents:: Topics


v2.0.0
======

Release Summary
---------------

Release v2.0.0 of the ``cisco.aci`` collection on 2020-12-15.
This changelog describes all changes made to the modules and plugins included in this collection since v1.1.1. 

Major Changes
-------------

- Change certificate_name to name in aci_aaa_user_certificate module for query operation

Minor Changes
-------------

- Add aci_node_mgmt_epg module to manage in band or out of band management EPGs
- Add aci_static_node_mgmt_address module & test file
- Add test file for aci_node_mgmt_epg

v1.1.1
======

Release Summary
---------------

Release v1.1.1 of the ``cisco.aci`` collection on 2020-11-23.
This changelog describes all changes made to the modules and plugins included in this collection since v1.1.0. 

Minor Changes
-------------

- Add test file for aci_domain_to_encap_pool
- aci_epg_to_domain moving child configs & classes to each domain type

Bugfixes
--------

- Fix galaxy import warnings
- Fix sanity issue in aci_epg_to_domain

v1.1.0
======

Release Summary
---------------

Release v1.1.0 of the ``cisco.aci`` collection on 2020-10-30.
This changelog describes all changes made to the modules and plugins included in this collection since v1.0.1. 

Minor Changes
-------------

- Ability to add monitoring policy to epgs and anps
- Add Ansible Network ENV to fallback
- Add aci_l3out_external_path_to_member.py & aci_l3out_static_routes modules
- Add env_fallback for common connection params
- Add env_fallback for the rest of the argument spec
- Add new Subclass path support
- Add new module and test file for leaf breakout port group
- Added failure message to aci_interface_policy_leaf_policy_group
- Update README.md
- Update inventory
- aci_epg_to_domain addition of promiscuous mode (#79)
- aci_interface_policy_port_security addition of attribute:timeout (#80)

Bugfixes
--------

- Existing_config variable is not reset during loop
- Fix galaxy import warnings
- Fix how validity of private key/private key file is checked to support new types
- Fix incorrect domain types in aci_domain_to_encap_pool module

v1.0.1
======

Release Summary
---------------

Release v1.0.1 of the ``cisco.aci`` collection on 2020-10-13.
This changelog describes all changes made to the modules and plugins included in this collection since v1.0.0. 

Minor Changes
-------------

- Enable/Disable infra vlan in aci_aep and its test module
- Set scope default value in aci_l3out_extsubnet

Bugfixes
--------

- Fix convertion of json/yaml payload to xml in aci_rest
- Fix dump of config for aci_rest
- Fix issue of "current" in firmware_source module
- Fix sanity issue in aci_rest and bump version to v1.0.1

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
