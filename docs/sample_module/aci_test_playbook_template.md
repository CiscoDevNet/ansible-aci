> [!NOTE]
> Remove comments that are used **only** for explanation purpose. Refer other test playbooks to verify.

```yaml
---

# Test code for the ACI modules
# Copyright: (c) <year>, <Name> (@<github id>)
# Replace <year>, <Name>, and <github id> with your information.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

- name: Test that we have an ACI APIC host, ACI username and ACI password
  fail:
    msg: 'Please define the following variables: aci_hostname, aci_username and aci_password.'
  when: aci_hostname is not defined or aci_username is not defined or aci_password is not defined

# 1. Verify ACI APIC host, username, and password are defined in inventory
# 2. Set ACI connection variables
- name: Set vars
  set_fact:
    aci_info: &aci_info
      host: "{{ aci_hostname }}"
      username: "{{ aci_username }}"
      password: "{{ aci_password }}"
      validate_certs: '{{ aci_validate_certs | default(false) }}'
      use_ssl: '{{ aci_use_ssl | default(true) }}'
      use_proxy: '{{ aci_use_proxy | default(true) }}"
      output_level: "{{ aci_output_level | default('info') }}"


# CLEAN TEST ENVIRONMENT BEFORE TESTS

# 1. Initial cleanup
# Ensures a clean state before tests begin by removing any existing objects.
- name: Remove the ansible_tenant (initial cleanup)
  aci_tenant:
    <<: *aci_info
    tenant: ansible_tenant
    state: absent

# 2. Setup if required
# Creates necessary parent objects or dependencies that your ACI module's object relies on.
- name: Add a new tenant (setup)
  aci_tenant:
    <<: *aci_info
    tenant: ansible_tenant
    description: Ansible tenant
    state: present

- name: Add a new parent object (setup)
  aci_l3out:
    <<: *aci_info
    tenant: ansible_tenant
    name: '<parent_object_name>' # Replace <parent_object_name> with the actual name
    description: Parent object description
    state: present

# 3. Create with minimum configuration (check/normal/idempotent)
# Adds a new object using only the required parameters.
# Each task registers its output for subsequent assertion.
- name: Add new object with min config (check mode)
  your_module_name:
    <<: *aci_info
    # ... min required parameters for your module ...
    state: present
  check_mode: true
  register: result_min_check

- name: Add new object with min config (normal mode)
  your_module_name:
    <<: *aci_info
    # ... min required parameters for your module ...
    state: present
  register: result_min_actual

- name: Add new object with min config (idempotency)
  your_module_name:
    <<: *aci_info
    # ... min required parameters for your module ...
    state: present
  register: result_min_idempotency

- name: Assert new object with min config
  assert:
    that:
      - result_min_check is changed == false
      - result_min_check.msg == "Would have created/modified object." # Example assertion
      - result_min_actual is changed == true
      - result_min_actual.current.name == "expected_name" # Replace with actual expected name/property
      - result_min_idempotency is changed == false

# 4. Update with full configuration (check/normal/idempotent)
# Adds or updates an object using all available parameters.
- name: Update object with full config (check mode)
  your_module_name:
    <<: *aci_info
    # ... all parameters for your module ...
    state: present
  check_mode: true
  register: result_full_check

- name: Update object with full config (normal mode)
  your_module_name:
    <<: *aci_info
    # ... all parameters for your module ...
    state: present
  register: result_full_actual

- name: Update object with full config (idempotency)
  your_module_name:
    <<: *aci_info
    # ... all parameters for your module ...
    state: present
  register: result_full_idempotency

- name: Assert update object with full config
  assert:
    that:
      - result_full_check is changed == true # Expect change if updating
      - result_full_check.msg == "Would have created/modified object."
      - result_full_actual is changed == true
      - result_full_actual.current.property == "expected_value" # Replace with actual expected property/value
      - result_full_idempotency is changed == false

# 5. Additional update cases
# Include specific scenarios for updating parameters, especially edge cases or conditional updates.
# ... (Add more update tasks and assertions as needed) ...

# 6. Additional create cases also used for query all
# Add more objects if needed to thoroughly test the "query all" functionality.
# ... (Add more create tasks for different objects if needed) ...

# 7. Queries
# Tasks to query a specific object and all objects of the module's class.
- name: Query a particular object
  your_module_name:
    <<: *aci_info
    # ... parameters to identify a single object to query ...
    state: query
  register: query_single_result

- name: Query all objects
  your_module_name:
    <<: *aci_info
    state: query
  register: query_all_result

- name: Assert query results
  assert:
    that:
      - query_single_result.current is defined
      - query_single_result.current.name == "expected_name" # Replace with actual expected name
      - query_all_result.current is defined
      - query_all_result.current | length > 0 # At least one object found
      - query_all_result.current | selectattr('name', 'equalto', 'expected_name') | list | length == 1 # Verify specific object is in list

# 8. Errors
# Tasks designed to trigger expected error conditions (e.g., missing required parameters, invalid values)
# and assert that the module fails gracefully with the correct error message.
# ... (Add error-inducing tasks and assertions) ...

# 9. Delete (check/normal/idempotent)
# Tasks to remove objects created during testing.
- name: Remove an object (check mode)
  your_module_name:
    <<: *aci_info
    # ... parameters to identify object to delete ...
    state: absent
  check_mode: true
  register: result_delete_check

- name: Remove an object (normal mode)
  your_module_name:
    <<: *aci_info
    # ... parameters to identify object to delete ...
    state: absent
  register: result_delete_actual

- name: Remove an object (idempotency)
  your_module_name:
    <<: *aci_info
    # ... parameters to identify object to delete ...
    state: absent
  register: result_delete_idempotency

- name: Assert remove object
  assert:
    that:
      - result_delete_check is changed == true
      - result_delete_check.msg == "Would have removed object."
      - result_delete_actual is changed == true
      - result_delete_actual.current is not defined # Object should no longer exist
      - result_delete_idempotency is changed == false

# CLEAN TEST ENVIRONMENT AFTER TESTS

# 10. Final cleanup
# Removes all objects created during the test run to leave the environment in a clean state.
# Removing the highest parent object (e.g., the tenant) is often sufficient.
- name: Remove the ansible_tenant (final cleanup)
  aci_tenant:
    <<: *aci_info
    tenant: ansible_tenant
    state: absent

```