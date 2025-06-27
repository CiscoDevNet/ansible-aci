#!/usr/bin/env bash

source <(grep = ../../inventory.networking)

for host in ${test_inventory_ips[@]} ;
  do
    echo $host
    echo "" > test.cisco_aci.yml # Create an empty inventory file
    echo "" > test.cisco_aci_invalid.yml # Create an empty inventory file for invalid input

    ansible-playbook playbooks/create_inventories.yml -e "template_name=cisco_aci_keyed_groups" -e "file_name=test.cisco_aci" -e "aci_host=${host}" -vvvv
    export ANSIBLE_INVENTORY=test.cisco_aci.yml # Set the inventory file to be used by the playbooks

    ansible-inventory --graph
    ansible-inventory --list
    ansible-playbook playbooks/role_controller.yml -vvvv
    # Uncomment to run the leaf role else will fail when the hosts are not defined in the inventory
    # ansible-playbook playbooks/role_leaf.yml -vvvv

    ansible-playbook playbooks/create_inventories.yml -e "template_name=cisco_aci" -e "file_name=test.cisco_aci" -e "aci_host=${host}" -vvvv
    ansible-inventory --list
    ansible-playbook playbooks/no_role_defined.yml -vvvv

    ansible-playbook playbooks/create_inventories.yml -e "template_name=cisco_aci_invalid_input" -e "file_name=test.cisco_aci" -e "aci_host=${host}" -vvvv
    ansible-inventory --list
    ansible-playbook playbooks/no_role_defined.yml -vvvv

    ansible-playbook playbooks/create_inventories.yml -e "template_name=cisco_aci_invalid_inventory_name" -e "file_name=test.cisco_aci_invalid" -e "aci_host=${host}" -vvvv
    export ANSIBLE_INVENTORY=test.cisco_aci_invalid.yml # Reset the inventory file to the invalid one

    ansible-inventory --list
    ansible-playbook playbooks/invalid.yml -vvvv
  done
