#!/usr/bin/env bash

# shellcheck source=../../inventory.networking
source ../../inventory.networking

# Ensure test_inventory_ips is defined and is an array
# Disabling the SC2154 warning to avoid sanity failures for ubuntu-latest (stable-2.16)
# shellcheck disable=SC2154
if [[ -z "${test_inventory_ips[*]}" ]]; then
  echo "Error: test_inventory_ips is not set or empty."
  exit 1
fi

HOSTS=("${test_inventory_ips[@]}")

for host in "${HOSTS[@]}"; do
  echo "$host"
  # Create empty inventory files
  : > test.cisco_aci.yml
  : > test.cisco_aci_invalid.yml

  ansible-playbook playbooks/create_inventories.yml -e "template_name=cisco_aci_keyed_groups" -e "file_name=test.cisco_aci" -e "aci_host=${host}" -vvvv
  export ANSIBLE_INVENTORY="test.cisco_aci.yml"

  ansible-inventory --graph
  ansible-inventory --list
  ansible-playbook playbooks/role_controller.yml -vvvv
  # Current tests are executed against ACI fabrics that only consist of controllers.
  # The tests can also be executed against ACI fabrics that consist of leaf switches.
  # Test will fail when the hosts types ( like leaf role ) are not defined in the dynamic inventory.
  # Uncomment the line below to execute test specific for the leaf role.
  # ansible-playbook playbooks/role_leaf.yml -vvvv

  ansible-playbook playbooks/create_inventories.yml -e "template_name=cisco_aci" -e "file_name=test.cisco_aci" -e "aci_host=${host}" -vvvv
  ansible-inventory --list
  ansible-playbook playbooks/no_role_defined.yml -vvvv

  ansible-playbook playbooks/create_inventories.yml -e "template_name=cisco_aci_invalid_input" -e "file_name=test.cisco_aci" -e "aci_host=${host}" -vvvv
  ansible-inventory --list
  ansible-playbook playbooks/no_role_defined.yml -vvvv

  ansible-playbook playbooks/create_inventories.yml -e "template_name=cisco_aci_invalid_inventory_name" -e "file_name=test.cisco_aci_invalid" -e "aci_host=${host}" -vvvv
  export ANSIBLE_INVENTORY="test.cisco_aci_invalid.yml"

  ansible-inventory --list
  ansible-playbook playbooks/invalid.yml -vvvv
done
