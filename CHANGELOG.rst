==========================================
Cisco ACI Ansible Collection Release Notes
==========================================

.. contents:: Topics


v2.1.0
======

Release Summary
---------------

Release v2.1.0 of the ``ansible-aci`` collection on 2021-10-06.
This changelog describes all changes made to the modules and plugins included in this collection since v2.0.0. 

Minor Changes
-------------

- Add APIC 5.x to inventory for Integration tests
- Add a requirements file
- Add ability to change custom epg name
- Add aci_cloud_ap module and test file
- Add aci_cloud_aws_provider module and its test file (#181)
- Add aci_cloud_bgp_asn module and test file (#180)
- Add aci_cloud_epg_selector module and test file (#182)
- Add aci_fabric_spine_profile, aci_fabric_spine_switch_assoc and aci_fabric_switch_block modules and integration tests (#187)
- Add aci_info
- Add aci_interface_description module and test file (#167)
- Add aci_l3out_bgp_peer and aci_l3out_interface modules and test files (#177)
- Add aci_snmp_client, aci_snmp_client_group, aci_snmp_community_policy, aci_snmp_policy and aci_snmp_user modules and test files (#176)
- Add aci_syslog_group module and test file (#170)
- Add aci_syslog_source and aci_syslog_remote_dest modules and test files (#174)
- Add aci_vmm_controller module and test file
- Add aci_vmm_vswitch module and test file (#142)
- Add check for enhanced lag policy
- Add cloud_external_epg and cloud_external_epg_selector modules and test files (#185)
- Add directory and aliases file for l3out node profile tests
- Add ethertype for IPv6
- Add ethertype ipv4
- Add functionality to support cryptography for signing
- Add galaxy-importer check (#115)
- Add ipv6_l3_unknown_multicast parameter support for aci_bd
- Add issue templates
- Add module aci_cloud_epg & test file (#175)
- Add module aci_l3out_logical_node_profile to manage l3out node profiles
- Add module and test for aci_contract_subject_to_service_graph
- Add new module aci_l2out_extepg_to_contract and test file based on aci_l3out_extepg_to_contract
- Add new modules for L2out - aci_l2out_logical_*
- Add primary_encap in module tests
- Add route_profile, route_profile_l3_out to aci_bd
- Add support and tests for custom_qos_policy parameter in aci_epg
- Add support for ANSIBLE_NET_SSH_KEYFILE
- Add support for vmm domain infra port group and tag collection in aci_domain module (#141)
- Add task to create requirement for enhanced lag policy
- Add test case for custom epg name
- Add test file for aci_bd
- Add tests for ipv6_l3_unknown_multicast parameter support in aci_bd
- Add tests for l3out node profile module
- Add tests to create multiple node profiles and query all node profiles in an L3out
- Add variable references and fix naming in l3out_node_profile tests
- Add version check for changing custom epg name
- Added Enhanced Lag Policy for VMware VMM Domain Profile in module aci_epg_to_domain
- Change CI to latest version of ansible and python 3.8
- Change child_configs & child_classes
- Change dscp to target_dscp in aci_l3out_logical_node_profile module to avoid future var conflicts
- Change naming of lagpolicy
- Change primary_encap --> primaryEncap
- Change test case for enhanced_lag_policy
- Changes made to execute aci_epg_to_domain and aci_cloud_cidr modules, also generalised the cloud variables
- Check WARNINGs and ERRORs in galaxy-importer check (#118)
- Correcting sanity in aci_static_binding_to_epg.py module
- Fix broken test parameters for aci_l3out_logical_interface_profile
- Fix documentation and add example to query all node profiles for L3out
- Fix feedback
- Fix indentation causing linting error
- Fix lag_plicy tDn
- Fix missed separators '/' in path attribute of ACIModule class
- Fix module reference and remove unused aliases in aci_l3out_logical_node_profile tests
- Fixed default values in docs and specs
- Fixed the behavior when output is specified in aci_rest. (#169)
- Initial changes to aci_cloud_ctx_profile module to execute only cloud sites from inventory
- Interface types added for Po's and vPC's using fex-ports and test files
- L3Out Enhancements
- L3Out Interface Profile (#134)
- Made changes in collection version segment
- Made changes in mso.py to generalize construct_url
- Made changes to support aci non cloud host >=3.2
- Made changes with respect to galaxy importer similar to MSO
- Modified 12 files affected from inventory file changes, by differentiating tasks into cloud and non-cloud specific hosts
- Move custom_qos_policy to conditional and remove unnecessary custom_qos_policy from monitoring policy in test
- Move ipv6_l3_unknown_multicast to condition and check version in test
- Remove uneccessary delegate_to variable for l3out_node_profile cleanup task
- Separated assert statements for cloud and non-cloud sites and added additional condition statement required for execution of version<=4.1
- Supports primaryEncap value as unknown (#157)
- Update aci_l3out_extepg_to_contract.py
- W291 + boolean correction
- contract_enhancements (#135)
- doc-required-mismatch fix
- interface blacklist test fix
- interface disable/enable fabricRsOosPath
- interface disable/enable fex support

Bugfixes
--------

- Fix blacklist bug
- Fix cleanup of MGMT EPGs
- Fix module reference for l3out_node_profile cleanup task
- Fix required variables for absent and present states for l3out_node_profile
- Fix sanity & importer check errors
- Fix test and assertion variables and module references for l3out_node_profile tests
- pylint fix for .format()

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
