**Table of Contents**

*   [Testing the Module](#testing-the-module)
    *   [Creating a Playbook to test the module](#creating-a-playbook-to-test-the-module)
        1.  [Initial cleanup](#initial-cleanup)
        2.  [Setup if required](#setup-if-required)
        3.  [Create with minimum configuration (check/normal/idempotent)](#create-with-minimum-configuration-checknormalidempotent)
        4.  [Update with full configuration (check/normal/idempotent)](#update-with-full-configuration-checknormalidempotent)
        5.  [Additional update cases](#additional-update-cases)
        6.  [Additional create cases also used for query all](#additional-create-cases-also-used-for-query-all)
        7.  [Queries](#queries)
        8.  [Errors](#errors)
        9.  [Delete (check/normal/idempotent)](#delete-checknormalidempotent)
        10. [Final cleanup](#final-cleanup) 
    *   [Integration Test](#integration-test)
    *   [Sanity Test](#sanity-test)
    *   [Additional Tests](#additional-tests)
    *   [Coverage Report](#coverage-report)  
 

# Testing the Module
Modules should be tested to make sure that it works for all states: present, absent, and query. The following section shows a basic and practical approach to building a **test playbook** with the help of a template. This makes it easier to complete the test file without having to write everything from scratch.

### Creating a Playbook to test the module

> Use the contents of test playbook from the template [ACI playbook template: docs/sample_module/aci_test_playbook_template.md](sample_module/aci_test_playbook_template.md) as reference.

1.  The **tests** directory of our collection includes the **integration** directory. The **integration** directory consists of **targets**, which has directories for all the test files of modules that currently exist in our collection. We go to the **targets** directory and copy the `aci_l3out_logical_node` directory, then paste it in the same directory as `aci_l3out_static_routes`, which should be the same as the name of our module. Upon opening the directory, we find the `main.yml` file. We open this file and make the following changes.

2.  The copyright section should be changed to APIC's credentials.

```yaml
# Copyright: (c) <year>, <Name> (@<github id>)
```

3.  The following section verifies that the ACI APIC host, ACI username, and ACI password are defined in the inventory. These will be used in every task of the test file. The inventory file is located in the inventory directory. More information on this directory is given below, after the test file.

```yaml
- name: Test that we have an ACI APIC host, ACI username and ACI password
  fail:
    msg: 'Please define the following variables: aci_hostname, aci_username and aci_password.'
  when: aci_hostname is not defined or aci_username is not defined or aci_password is not defined
```

4.  The next section should remain as is. `set_fact` stores the values of variables such as `aci_hostname`, `aci_username`, etc. in `&aci_info`. This will be referenced in all tasks.

```yaml
    # GET Credentials from the inventory
    - name: Set vars
      set_fact:
        aci_info: &aci_info
          host: "{{ aci_hostname }}"
          username: "{{ aci_username }}"
          password: "{{ aci_password }}"
          validate_certs: '{{ aci_validate_certs | default(false) }}'
          use_ssl: '{{ aci_use_ssl | default(true) }}'
          use_proxy: '{{ aci_use_proxy | default(true) }}'
          output_level: "{{ aci_output_level | default('info') }}"
```

The test cases for the ACI modules follow a consistent pattern across operations such as Create, Update, Query, Query all, and Delete. For Create, Update, and Delete operations, the tests includes:

*   `Check mode`:  The check mode task to simulate the operation without making changes.
*   `Normal mode`: The normal_mode task to perform the actual operation.
*   `Idempotent`: The normal mode tasks to verify idempotency, ensuring that running the operation again does not cause changes.
*   `Assert`: The assert tasks are then used to validate this registered output of the CRUD tasks against the expected configuration or state. This ensures that the module behaves as intended and that the changes are correctly applied or reflected.

This structured approach ensures thorough testing of the modules' functionality and stability in different modes and repeated executions.

Here's the structured approach for the `main.yml` test file:

1.  **Initial cleanup**
    *   This section ensures a clean slate before tests begin. Any existing objects that might interfere with the test run are removed.

    ```yaml
    - name: Remove the ansible_tenant (initial cleanup)
      aci_tenant:
        <<: *aci_info
        tenant: ansible_tenant
        state: absent
    ```

    > **Note**: A cleanup section is included before we start testing to remove any existing objects, ensuring a clean state.

2.  **Setup if required**
    *   This includes creating any necessary parent objects or dependencies that ACI module's object relies on.

    ```yaml
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
        name: '<parent_object_name>' # Replace <parent_object_name> with the actual name of the parent object, e.g., ansible_l3out
        description: Parent object description
        state: present
    ```

3.  **Create with minimum configuration (check/normal/idempotent)**
    *   Tasks to add a new object using only the required parameters.
    *   Each task will `register` its output for subsequent assertion.

    ```yaml
    - name: Add new object with min config (check mode)
      your_module_name:
        <<: *aci_info
        # ... min required parameters ...
        state: present
      check_mode: true
      register: result_min_check

    - name: Add new object with min config (normal mode)
      your_module_name:
        <<: *aci_info
        # ... min required parameters ...
        state: present
      register: result_min_actual

    - name: Add new object with min config (idempotency)
      your_module_name:
        <<: *aci_info
        # ... min required parameters ...
        state: present
      register: result_min_idempotency

    - name: Assert new object with min config  # Example assertion
      assert:
        that:
          - result_min_check is changed == false
          - result_min_check.msg == "Would have created/modified object."
          - result_min_actual is changed == true
          - result_min_actual.current.name == "expected_name"
          - result_min_idempotency is changed == false
    ```

4.  **Update with full configuration (check/normal/idempotent)**
    *   Tasks to add or update an object using all available parameters.

    ```yaml
    - name: Update object with full config (check mode)
      your_module_name:
        <<: *aci_info
        # ... all parameters ...
        state: present
      check_mode: true
      register: result_full_check

    - name: Update object with full config (normal mode)
      your_module_name:
        <<: *aci_info
        # ... all parameters ...
        state: present
      register: result_full_actual

    - name: Update object with full config (idempotency)
      your_module_name:
        <<: *aci_info
        # ... all parameters ...
        state: present
      register: result_full_idempotency

    - name: Assert update object with full config (idempotency)
      assert:
        that:
          - result_full_check is changed == true # Expect change if updating
          - result_full_check.msg == "Would have created/modified object."
          - result_full_actual is changed == true
          - result_full_actual.current.property == "expected_value"
          - result_full_idempotency is changed == false
    ```

5.  **Additional update cases**
    *   Include specific scenarios for updating parameters, especially edge cases or conditional updates.

6.  **Additional create cases also used for query all**
    *   Add more objects if needed to thoroughly test the "query all" functionality.

7.  **Queries**
    *   **Query one**: Task to query a specific object.
    *   **Query all**: Task to query all objects of the module's class.
    *   Assert tasks to verify the correct data is returned.

    ```yaml
    - name: Query a particular object
      your_module_name:
        <<: *aci_info
        # ... parameters to identify a single object ...
        state: query
      register: query_single_result

    - name: Query all objects
      your_module_name:
        <<: *aci_info
        state: query
      register: query_all_result

    - name: Assert query all objects
      assert:
        that:
          - query_single_result.current is defined
          - query_single_result.current.name == "expected_name"
          - query_all_result.current is defined
          - query_all_result.current | length > 0 # At least one object found
          - query_all_result.current | selectattr('name', 'equalto', 'expected_name') | list | length == 1 # Verify specific object is in list
    ```

8.  **Errors**
    *   Tasks designed to trigger expected error conditions (e.g., missing required parameters, invalid values) and assert that the module fails gracefully with the correct error message.

9.  **Delete (check/normal/idempotent)**
    *   Tasks to remove objects created during testing.

    ```yaml
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

    - name: Assert remove object (idempotency)
      assert:
        that:
         - result_delete_check is changed == true
          - result_delete_check.msg == "Would have removed object."
          - result_delete_actual is changed == true
          - result_delete_actual.current is not defined # Object should no longer exist
          - result_delete_idempotency is changed == false
    ```

10. **Final cleanup**
    *   This section removes all objects created during the test run to leave the environment in a clean state. Removing the highest parent object (e.g., the tenant in most cases) is often sufficient, as it will cascade delete its children.

    ```yaml
    - name: Remove the ansible_tenant (final cleanup)
      aci_tenant:
        <<: *aci_info
        tenant: ansible_tenant
        state: absent
    ```


## Integration Test

ACI integration tests are end-to-end tests performed to check that the code path functions of our collection are working as expected.

Steps required to perform tests:
1. The test playbook created in `tests/integration/targets` directory
2. Update the inventory file with the credentials of the APIC in  `ansible-aci -> tests -> integration -> inventory.networking`. Ansible uses an inventory file to keep track of which hosts are part of the APIC, and how to reach them for running commands and playbooks using credentials for the APIC.

```ini
[aci]
<apic-label-name> ansible_host=<apic-host> ansible_connection=local aci_hostname=<apic-host>
aci_username=<apic-username> aci_password= <apic-password>
```

2.  Go to **ansible-aci** in the terminal and test the new module with the test playbook using the following commands. To make it easier to run all the commands in one go, we store the commands in a script and run the script.

```text
rm -rf cisco-aci-*
ansible-galaxy collection build --force
ansible-galaxy collection install cisco-aci-* --force
cd ~/.ansible/collections/ansible_collections/cisco/aci
ansible-test network-integration --docker --color --truncate 0 -vvv --coverage aci_<ACI module name>
```

*   `ansible-galaxy collection build --force` builds a collection artifact that can be stored in a central repository. By default, this command builds from the current working directory, which in our case is ansible-aci.

*   `ansible-galaxy collection install cisco-aci-* --force` installs the built collection in our current working directory, ansible-aci.

*   `cd ~/.ansible/collections/ansible_collections/cisco/aci` changes our directory to aci, where tests are performed.

*   `ansible-test network-integration --docker --color --truncate 0 -vvv --coverage aci_<ACI module name>` is used to run integration tests inside Docker. We can either run the integration test on one module or all the modules by omitting the name altogether.

## Sanity Test

Sanity tests are performed on our module to make sure that it adheres to Ansible coding standards. A few examples include verifying whether our module's documentation is supported on all Python versions, and checking YAML files for syntax and formatting issues, etc.

Add the below line in the script to run sanity test:

```text
ansible-test sanity --docker --color --truncate 0 -vvv --coverage aci_<ACI module name>
```

*   `ansible-test sanity --docker --color --truncate 0 -vvv --coverage aci_<ACI module name>` is used to run sanity tests inside Docker, which already has all the dependencies.

*   The sanity task runs on Ubuntu with multiple Ansible versions in parallel, installing Python, Ansible base, coverage tool, and the Cisco ACI collection. It then executes the sanity tests with coverage enabled inside a Docker environment, generates a coverage XML report grouped by command and version, and finally uploads the coverage report to codecov.io.
    *   The sanity report verifies that the core functionalities of the Cisco ACI Ansible collection work correctly across multiple supported Ansible versions in a consistent environment.
    *   On any test failures or coverage regressions, the root cause should be investigated promptly by reviewing logs and error messages.
    *   Issues should be fixed or escalated as appropriate, and the sanity tests re-run to confirm resolution before further development or deployment.

    This approach ensures that the collection remains stable and reliable across supported Ansible versions, with visibility into test completeness and quality.

## Additional Tests 

Additional tests are added to verify the formatting of the code, such as checking for trailing spaces, tabs, and other formatting issues. These tests can be found in the **workflows** -> **ansible-test.yml** file.
    *   **galaxy-importer**: a tool used within Ansible Galaxy to import and validate collections of Ansible content.
    *   **black**: a Python code formatter that enforces a consistent style. It automatically formats Python code to conform to the PEP 8 style guide.
        *   run the below black command before testing sanity.

```text
black <path_to_file/file_name.py> -l 159
```

## Coverage Report

Code coverage reports are generated in HTML format and make it easy for us to identify untested code for which more tests should be written.

Steps required to perform tests:

```text
ansible-test coverage report
ansible-test coverage html
open ~/.ansible/collections/ansible_collections/cisco/aci/tests/output/reports/coverage/index.html
```

*   We add the `--coverage` option to any test command to collect code coverage data:
    1.  `ansible-test coverage report`
    2.  `ansible-test coverage html`
    3.  `open ~/.ansible/collections/ansible_collections/cisco/aci/tests/output/reports/coverage/index.html`

    *   In the Ansible test coverage report generated by commands like `ansible-test coverage report` and `ansible-test coverage html`, the colors green, yellow, and red indicate the extent of code coverage for ACI modules:

        *   **Green**: Represents well-covered code sections where tests have executed the code paths. This indicates good test coverage and confidence in the tested code.
        *   **Yellow**: Indicates partial coverage or code that is executed but not fully tested. This suggests areas where tests could be improved or expanded.
        *   **Red**: Marks code that is not covered by any tests. These are gaps in testing that could lead to undetected bugs or issues.

> [!NOTE]
> The main() function, when guarded by if __name__ == "__main__":, is often skipped during module imports for testing, leading to its code not being executed by test suites. Consequently, if its specific execution path isn't explicitly invoked by tests, it can appear as uncovered in coverage reports.  

> [!TIP]
> A common best practice is to aim for 100% coverage to ensure sufficient testing. While high coverage is desirable, 100% coverage is often not achievable due to untestable corner cases or environment constraints. It is important to still strive for coverage higher than 95% and to document any known gaps in testing.