Testing the Module
============

Modules should be tested to make sure that it works for all states: present, absent, and query. The following section shows a basic and practical approach to building a test file with the help of another test file. This makes it easier to complete the test file without having to write everything from scratch.


1. The **tests** directory of our collection includes the **integration** directory. The **integration** directory consists of **targets**, which has directories for all the test files of modules that currently exist in our collection. We go to the **targets** directory and copy the aci_l3out_logical_node directory, then paste it in the same directory as aci_l3out_static_routes, which should be the same as the name of our module. Upon opening the directory, we find the main.yml file. We open this file and make the following changes.

2. The copyright section should be changed to your credentials.

.. code-block:: yaml

  # Copyright: (c) <year>, <Name> (@<github id>)

2. The following section verifies that  the ACI APIC host, ACI username, and ACI password are defined in the inventory. These will be used in every task of the test file. The inventory file is located in the inventory directory. More information on this directory is given below, after the test file.

.. code-block:: yaml

  - name: Test that we have an ACI APIC host, ACI username and ACI password
    fail:
      msg: 'Please define the following variables: aci_hostname, aci_username and aci_password.'
    when: aci_hostname is not defined or aci_username is not defined or aci_password is not defined

3. The next section should remain as is. set_fact stores the values of variables such as aci_hostname, aci_username, etc. in &aci_info. This will be referenced in all tasks.

.. code-block:: yaml

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

4. The next section deletes the tenant. This ensures that we don't have the root object configuration on our APIC. This is done to avoid idempotency issues later during the creation of other objects pertaining to our module. We verify the result of each task in the test file, which also checks for idempotency. If an object such as the tenant already exists before the test begins, these verification tests may fail.

.. code-block:: yaml

  - name: Remove the ansible_tenant
    aci_tenant:
      <<: *aci_info 
      tenant: ansible_tenant
      state: absent

.. note::

  - A cleanup section is included before we start testing to remove any existing objects, ensuring a clean state. 
  - Another cleanup section is added after testing to delete created objects, since not all objects are explicitly defined within the tenant.

The test cases for the ACI modules follow a consistent pattern across operations such as Create, Update, Query, Query all, and Delete. For Create, Update, and Delete operations, each test includes:

  + The check mode task to simulate the operation without making changes.
  + The normal_mode task to perform the actual operation.
  + The normal mode tasks to verify idempotency, ensuring that running the operation again does not cause changes.
  + After the operations, the test verifies the output files and asserts that the changes occurred as expected or not changed when re-run in check_mode, confirming the module's correct behavior and idempotency.  

This structured approach ensures thorough testing of the modules' functionality and stability in different modes and repeated executions.


5. We begin by adding tasks to post configuration to the APIC. This includes creation of all the classes such as tenant and l3out that were used in the construct_url function in our module.

.. code-block:: yaml

      - name: Add a new tenant
        aci_tenant:
          <<: *aci_info 
          tenant: ansible_tenant
          description: Ansible tenant
          state: present

      - name: Add a new parent object
        aci_l3out:
          <<: *aci_info
          tenant: ansible_tenant
          name: '<parent_object_name>' # Replace <parent_object_name> with the actual name of the parent object, e.g., ansible_l3out
          description: Parent object description
          state: present


.. code-block:: text

6. The next section consists of adding tasks for all aspects of our module. We include Ansible's register attribute to save the result of the task. The procedure is as follows:

* Tasks to clean the environment to begin with a clean slate.
        * Task to add a new object with only the required parameters. (check mode) -> where the check_mode is set to true.
        * Task to add a new object with only the required parameters. (actual run) -> where the check_mode is set to false.
        * task to add a new object with only the required parameters again. (idempotency), to test the idempotency of the module.
        * An assert task to verify the object was created successfully for the previous tasks of adding new object with only the required parameters.(check mode, actual run and idempotency).
        * Task to add a new object with all the parameters. (check mode) -> where the check_mode is set to true.
        * Task to add a new object with all the parameters. (actual run) -> where the check_mode is set to false.
        * Task to add a new object with all the parameters again. (actual run), to test the idempotency of the module.
        * An assert task to verify the object was created successfully for the previous tasks of adding new object with all the parameters. (check mode, actual run and idempotency).
        * Task to update the object parameters. (check mode) -> where the check_mode is set to true.
        * Task to update the object parameters. (actual run) -> where the check_mode is set to false.
        * Task to update the object parameters again. (actual run), to test the idempotency of the module.
        * An assert task to verify the object was updated successfully for the previous tasks of updating object parameters. (check mode, actual run and idempotency).
        * Task to query a particular object.
        * Task to query all objects.
        * An assert task to verify the object was queried successfully for the previous tasks of querying a particular object and querying all objects.
        * Task to remove an object. (check mode) -> where the check_mode is set to true.
        * Task to remove an object. (actual run) -> without check_mode.
        * Task to remove an object again. (actual run), to test the idempotency of the module.
        * An assert task to verify the object was removed successfully for the previous tasks of removing an object. (check mode, actual run and idempotency).
        * Tasks to clean the environment to make sure there are no residual configurations.


.. code-block:: text

After inclusion of all the tasks, the configuration has been posted, modified, and deleted on our APIC. By using the values registered with results after each task, we can verify these results by comparing them with the expected response from the APIC. The result stored in the registered value is a list of dictionaries, and we access the attributes using the dot operator. If all the verifications below pass, our testing is complete.

.. code-block:: yaml

      - name: Verify if the object is created
        assert:
          that:
            - registered_value is changed
            - registered_value.attributes.object_id == object_id
            - registered_value.attributes.object_prop1 == object_prop1

Sanity Checks, Testing ACI Integration, and Generating Coverage Report
----------------------------------------------------------------------
Sanity tests are performed on our module to make sure that it adheres to Ansible coding standards. A few examples include verifying whether our module's documentation is supported on all Python versions, and checking YAML files for syntax and formatting issues, etc.

ACI integration tests are end-to-end tests performed to check that the code path functions of our collection are working as expected.

Code coverage reports are generated in HTML format and make it easy for us to identify untested code for which more tests should be written.

Steps required to perform tests:

1. Ansible uses an inventory file to keep track of which hosts are part of your APIC, and how to reach them for running commands and playbooks using credentials for the APIC. To update the inventory, go to **ansible-aci -> tests -> integration -> inventory.networking** and update the file with the credentials of your APIC.

.. code-block:: ini

  [aci]
  <apic-label-name> ansible_host=<apic-host> ansible_connection=local aci_hostname=<apic-host> 
  aci_username=<apic-username> aci_password= <apic-password>

2. Go to **ansible-aci** in the terminal and test the new module using the following commands. To make it easier to run all the commands in one go, we store the commands in a script and run the script.

.. code-block:: Blocks

      rm -rf cisco-aci-*
      ansible-galaxy collection build --force
      ansible-galaxy collection install cisco-aci-* --force
      cd ~/.ansible/collections/ansible_collections/cisco/aci
      ansible-test sanity --docker --color --truncate 0 -v
      ansible-test network-integration --docker --color --truncate 0 -vvv --coverage aci_<your module name>
      ansible-test coverage report
      ansible-test coverage html
      open ~/.ansible/collections/ansible_collections/cisco/aci/tests/output/reports/coverage/index.html


* ansible-galaxy collection build --force builds a collection artifact that can be stored in a central repository. By default, this command builds from the current working directory, which in our case is ansible-aci.

* ansible-galaxy collection install cisco-aci-* --force installs the built collection in our current working directory, ansible-aci.

* cd ~/.ansible/collections/ansible_collections/cisco/aci changes our directory to aci, where tests are performed.

* ansible-test sanity --docker --color --truncate 0 -v is used to run sanity tests inside Docker, which already has all the dependencies.

* ansible-test network-integration --docker --color --truncate 0 -vvv --coverage aci_<your module name> is used to run integration tests inside Docker. We can either run the integration test on one module or all the modules by omitting the name altogether.

* We add the --coverage option to any test command to collect code coverage data:
    1. ansible-test coverage report
    2. ansible-test coverage html
    3. open ~/.ansible/collections/ansible_collections/cisco/aci/tests/output/reports/coverage/index.html

    + In the Ansible test coverage report generated by commands like ansible-test coverage report and ansible-test coverage html, the colors green, yellow, and red indicate the extent of code coverage for your modules:

        + Green: Represents well-covered code sections where tests have executed the code paths. This indicates good test coverage and confidence in the tested code.
        + Yellow: Indicates partial coverage or code that is executed but not fully tested. This suggests areas where tests could be improved or expanded.
        + Red: Marks code that is not covered by any tests. These are gaps in testing that could lead to undetected bugs or issues.

    .. note:: A common best practice is to aim for 100% coverage to ensure sufficient testing. While high coverage is desirable, 100% coverage is often not achievable due to untestable corner cases or environment constraints. It is important to still strive for coverage higher than 95% and to document any known gaps in testing.

* The sanity task runs on Ubuntu with multiple Ansible versions in parallel, installing Python, Ansible base, coverage tool, and the Cisco ACI collection. It then executes the sanity tests with coverage enabled inside a Docker environment, generates a coverage XML report grouped by command and version, and finally uploads the coverage report to codecov.io.
  + The sanity report verifies that the core functionalities of the Cisco ACI Ansible collection work correctly across multiple supported Ansible versions in a consistent environment.
  + On any test failures or coverage regressions, the root cause should be investigated promptly by reviewing logs and error messages.
  + Issues should be fixed or escalated as appropriate, and the sanity tests re-run to confirm resolution before further development or deployment.

  This approach ensures that the collection remains stable and reliable across supported Ansible versions, with visibility into test completeness and quality.


* Additional tests added to verify the formatting of the code, such as checking for trailing spaces, tabs, and other formatting issues. These tests can be found in the **workflows** -> **ansible-test.yml** file.
  + galaxy-importer: a tool used within Ansible Galaxy to import and validate collections of Ansible content.
  + black: a Python code formatter that enforces a consistent style. It automatically formats Python code to conform to the PEP 8 style guide.
    + run the below black command before testing sanity.

    .. code-block:: text

      black <path_to_file/file_name.py> -l 159
