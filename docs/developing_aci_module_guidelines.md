# Developing Cisco ACI modules

This guide is intended for developers who want to contribute code, bug fixes, or new modules to the Cisco ACI-Ansible collection. It provides step-by-step instructions and outlines the standards and conventions to follow when making contributions.

For additional details about Cisco ACI, please refer to the [Cisco ACI user guide](https://www.cisco.com/c/en/us/solutions/collateral/data-center-virtualization/application-centric-infrastructure/solution-overview-c22-741487.html).

What is covered in this section:

Here's the Table of Contents for the Markdown content:

**Table of Contents**

*   [Developing Cisco ACI modules](#developing-cisco-aci-modules)
    *   [Introduction](#introduction)
    *   [Development Environment](#development-environment)
        *   [Git contribution workflow for ACI collection](#git-contribution-workflow-for-aci-collection)
        *   [Tools required for installation and build](#tools-required-for-installation-and-build)
        *   [ACI Collection structure](#aci-collection-structure)
    *   [Building a new module](#building-a-new-module)
        *   [Copyright Section](#copyright-section)
        *   [Documentation Section](#documentation-section)
        *   [Notes and Additional Sections](#notes-and-additional-sections)
        *   [Examples Section](#examples-section)
        *   [Return Section](#return-section)
        *   [Importing objects from Python libraries](#importing-objects-from-python-libraries)
        *   [Defining the argument_spec variable](#defining-the-argument_spec-variable)
        *   [Using the AnsibleModule object](#using-the-ansiblemodule-object)
        *   [Mapping variable definition](#mapping-variable-definition)
        *   [Using the ACIModule object](#using-the-acimodule-object)
            *   [Constructing URLs](#constructing-urls)
            *   [Getting the existing configuration](#getting-the-existing-configuration)
            *   [When state is present](#when-state-is-present)
                *   [Building the ACI payload](#building-the-aci-payload)
                *   [Performing the request](#performing-the-request)
            *   [When state is absent](#when-state-is-absent)
            *   [Exiting the module](#exiting-the-module)
    *   [Testing the Module](#testing-the-module)
        *   [Additional checks before making a Pull Request](#additional-checks-before-making-a-pull-request)  
 


## Introduction
The [cisco.aci collection](https://galaxy.ansible.com/cisco/aci) already includes a large number of Cisco ACI modules; however, the ACI object model is extensive, and covering all possible functionality would easily require more than 1,500 individual modules. Therefore, Cisco develops modules requested on a just-in-time basis.

If a specific functionality is required, there are three options:

- Open an issue using https://github.com/CiscoDevNet/ansible-aci/issues/new/choose so that Cisco developers can build, enhance, or fix the modules. If you have a Cisco support contract, contact Cisco TAC to open an issue for you.
- Learn the ACI object model and utilize the low-level APIC REST API using the [aci_rest](https://docs.ansible.com/ansible/latest/collections/cisco/aci/aci_rest_module.html) module.
- Contribute to Cisco's ansible-aci project by writing dedicated modules, proposing a fix or an enhancement, and becoming part of the Cisco ansible-aci community.

This guide will concentrate on the third option to demonstrate how to build a module, fix an issue, or improve an existing module and contribute it back to the ansible-aci project. The initial step in this process is to retrieve the latest version of the ansible-aci collection code. By retrieving the latest version, one will be able to modify existing code.

## Development Environment

### Git contribution workflow for ACI collection
To contribute effectively, first fork the [ACI repository](https://github.com/CiscoDevNet/ansible-aci) to your GitHub account, then clone your fork locally, and finally create a feature branch named after the specific change (e.g., new_l3out_static_routes_docs).

> Branching isolates development for bug fixes and new features. Always create a dedicated branch from `master` for modifications. This maintains a clean local `master` synchronized with the upstream, simplifying future updates and preventing complex merge/rebase operations.

> To understand more about the Git contribution workflow, refer to the [Git contribution workflow for ACI collection](aci_collection_git_contribution_workflow.md)


### Tools required for installation and build

Before building or testing the modules, ensure all required tools are installed. The full list of dependencies and setup instructions are documented in the collection's [README.md](https://github.com/CiscoDevNet/ansible-aci?tab=readme-ov-file#ansible-aci) file. This includes guidance on installing Python packages, Ansible collections, linters, and other development tools needed for module creation and testing.

### ACI Collection structure

The structure of the cisco.aci collection which consists of directories and files that are in ansible-aci repository. To further explore the cisco.aci collection structure in detail, refer [ACI collection structure](aci_collection_structure.md).

## Building a new module
There are two recommended approaches for creating a new Ansible module in the Cisco ACI collection:
1. Use the template module provided in [docs/sample_module/aci_module_template.md](sample_module/aci_module_template.md)
2. Repurpose an existing module from the collection that is functionally or hierarchically similar

Both methods ensure consistency with the existing module structure, coding conventions, and integration practices within the collection.

To create a new module from scratch, this document follows the first approach:
> * copy the python code from the template module provided in [docs/sample_module/aci_module_template.md](sample_module/aci_module_template.md)
> * Create a new python file in the plugins/modules directory of the collection named aci_<name_of_module>.py, where <name_of_module> is the name of the module being created.
> * Paste the copied contents of the template module into the newly created python file.

This approach simplifies the creation of a new module without requiring everything to be written from scratch.

### Copyright Section

Change the copyright section by replacing <year> by current year, <name> by author's name and <author_github_handle> by author's github handle:

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) <year>, <Name> (<author_github_handle>)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}
```

> [!NOTE]
> The above code block remains unchanged, except for the copyright section, which must be updated.

### Documentation Section

Each Ansible module must include a properly structured DOCUMENTATION section that clearly explains the module's purpose, usage, and parameters and follow the Ansible documentation guidelines.

Start by updating the following:
* Module name: the name of the module should be aci_<name_of_module>, where <name_of_module> is the name of the module being created. It should be same as the file name the module is being created in.
* Short description of what the module does
* Detailed description explaining the operations performed on the object

This must be followed by the options section, which defines all the input parameters the module accepts.

**Options Section**

The options section lists all parameters that will be defined in the module's argument_spec. This includes:
* object_id
* Configurable properties of the object
* Parent object reference
* Any additional required parameters
* state

Each parameter should define:
* description: Clear and concise explanation of the parameter's purpose
* type: Data type (e.g., str, int, bool)
* aliases: (if applicable)
* choices: (if applicable)
* default: (if applicable)

- Description must be clear and concise, providing enough detail for users to understand the purpose and usage of the object.
- Description must include specific details about the object, such as its purpose, how it is used, and any important considerations.
* For example,
    + The APIC defaults to `default_value` when unset during creation. Explains that when an object value is not explicitly provided in a task, the APIC automatically assigns a default value to that object.
    + The object_prop1 must be in the range 1 to 100. The default value is 50.
    + The object_prop3 is only applicable when using 'object_prop2' is set to <specific_value>.
    + default: <xyz> , the default values should not be provided for configuration arguments, unless API adds a default_value to the payload when creating the object. Default values could cause unintended changes to the object.
    + required: true; should be used only for parameters that are mandatory in all the states (present,query,absent) of the module. This ensures that users must provide a value for these parameters when using the module.

> [!NOTE]
> If a parameter is required in some states but not in others, then it should **NOT** be marked as required: true. Instead, it should be added in the argument_spec with the appropriate required_if conditions.

### extends_documentation_fragment section

The options section must be followed by the extends_documentation_fragment section, which allows modules to reuse standard documentation elements shared across the ACI collection.

Common documentation fragments are located in the plugins/doc_fragments/ directory of the collection and typically include:
* `cisco.aci.aci`: **Always included**; defines common ACI parameters such as host, username, password, etc.
* `cisco.aci.annotation`: Include if the module supports the *annotation* parameter.
* `cisco.aci.owner`: Include if the module supports the *owner* parameter.

The format of `DOCUMENTATION` section is as follows:

```yaml
DOCUMENTATION = r"""
---
module: aci_<name_of_module>
short_description: Short description of the module being created (config:<name_of_class>).
description:
- Functionality one.
- Functionality two.
options:
  object_id:
    description:
    - Description of the object.
    type: Data type of object eg. 'str'
    aliases: [ Alternate name of the object ]
  object_prop1:
    description:
    - Description of property one.
    type: Property's data type eg. 'int'
    choices: [ choice one, choice two ]
  object_prop2:
    description:
    - Description of property two.
    - This attribute is only configurable in ACI versions 6.0(2h) and above.
    type: Property's data type eg. 'bool'
  object_prop3:
    description:
    - Description of property three.
    - The APIC defaults to C(default_value) when unset during creation.
    - The object_prop3 is only applicable when using 'object_prop2' is set to <specific_value>.
    - The object_prop3 must be in the range 1 to 100. The default value is 50.
    type: Property's data type eg. 'str'
    required: true
  child_object_prop:
    description:
    - Description of the child class object property
    - This is required for child class object B(config:<name_of_child_class>)
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
```

### Notes and Additional Sections

Following the options and extends_documentation_fragment sections, include the following elements in the DOCUMENTATION block:
* **notes**: Use this section to document any important dependencies or relationships with other modules in the collection. This is especially useful when the module relies on a parent object or must be used in conjunction with another module.
* **see_also**: Provide references to related modules or the underlying ACI class (e.g., the REST API class or managed object) that the module interfaces with. This helps users understand the source and behavior of the module.
* **author**: At the end of the documentation block, include the contributor's name and GitHub handle.

The format of the notes and see_also sections is as follows:

```yaml
notes:
- The C(root_object), C(parent_object), C(object_prop), used must exist before using this module in your playbook.
The M(cisco.aci.aci_root_object_module) and M(cisco.aci.parent_object_module) modules can be used for this.
seealso:
- module: cisco.aci.aci_root_object_module
- module: cisco.aci.aci_parent_object_module
- name: APIC Management Information Model reference
description: More information about the internal APIC class B(config:<name_of_class>).
link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- <author's name> (<author's github id>)
"""
```

### Examples Section

The EXAMPLES section provides practical usage patterns for the module and must include complete Ansible tasks that serve as references for users building playbooks.

* Please note that 'remove an object' and 'query an object' will only contain the object name and no object parameters. "Query All" will not have any parameters other than the one that are set to required to construct the dn, ensuring that all the objects of the class being worked upon are returned.
* The example section must include Add, Query a single object, Query all objects, and Remove operations that can be performed using the module.
* Each example should include the required parameters and the expected state of the object.

> Ensure the examples demonstrate realistic use cases, include proper indentation, and adhere to the module's expected argument structure, as these examples are often used directly in playbooks.

The format of this section is shown below:

```yaml
EXAMPLES = r"""
- name: Add a new object
  cisco.aci.aci_<name_of_module>:
    host: apic
    username: admin
    password: SomeSecretePassword
    object_id: id
    object_prop1: prop1
    object_prop2: prop2
    state: present
  delegate_to: localhost

- name: Query an object
  cisco.aci.aci_<name_of_module>:
    host: apic
    username: admin
    password: SomeSecretePassword
    object_id: id
    state: query
  delegate_to: localhost

- name: Query all objects
  cisco.aci.aci_<name_of_module>:
    host: apic
    username: admin
    password: SomeSecretePassword
    state: query
  delegate_to: localhost

- name: Remove an object
  cisco.aci.aci_<name_of_module>:
    host: apic
    username: admin
    password: SomeSecretePassword
    object_id: id
    state: absent
  delegate_to: localhost
"""
```

### Return Section

The RETURN section defines the structure and content of the output returned after execution.
It is used in every module and has the same content, so copy and paste it from any module and do not modify it.

Refer to the `RETURN` section in any existing module in the collection or the aci_module_template.md file in [docs/sample_module/aci_module_template.md](sample_module/aci_module_template.md) for complete content.

```python
RETURN = r"""
  current:
    ...
"""
```

### Importing objects from Python libraries

The import section is generally consistent across ACI modules and usually does not require changes. However, if a new shared method or utility is added to the library, it may need to be imported explicitly.

The following imports are standard across ACI modules:

```python
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
```

* `ansible.module_utils.aci` import the superclass `ACIModule` and the `aci_argument_spec` definition from the library in plugins/module_utils/aci.py file.
    * `ACIModule` is imported because it has basic functions to make API requests and other capabilities that allow modules to manipulate objects.
    * **aci_argument_spec** is used by all the modules as it allows them to accept shared parameters such as username and password.
* If the module supports the annotation or owner parameters, also import **aci_annotation_spec** and **aci_owner_spec** respectively (as needed).

Similarly, the AnsibleModule is imported to leverage the common structure for building Ansible modules in Python.

> [!TIP]
> To understand more about the AnsibleModule, refer to the [Ansible documentation](https://docs.ansible.com/ansible/latest/dev_guide/developing_program_flow_modules.html#ansiblemodule).

* **Importing ACI Constants**: These constants, defined in plugins/module_utils/constants.py, provide standardized values and mapping dictionaries that help normalize ACI-specific parameters across modules.

```python
# Importing constants for ACI modules when needed.
# This import is used to access predefined constants and mappings for ACI objects.
from ansible_collections.cisco.aci.plugins.module_utils.constants import *
```

> [!TIP]
> * The '*' <ins>should</ins> be replaced with the specific constants needed, such as:
`from ansible_collections.cisco.aci.plugins.module_utils.constants import FILTER_PORT_MAPPING, IPV4_REGEX`



### Defining the argument_spec variable

In the `main()` function, the argument_spec variable defines all arguments required by the module and is based on the shared aci_argument_spec. All parameters previously defined in the DOCUMENTATION section should be added here.

The **argument_spec** provides a base set of common arguments (such as APIC credentials and connection details), and **argument_spec.update()** is used to define additional parameters specific to the module being developed.

> [!TIP]
>  For more information on how argument_spec works, refer to the [Ansible Argument Spec](https://docs.ansible.com/ansible/latest/dev_guide/developing_program_flow_modules.html#argument-spec).

Common parameters to include:
* The **object_id** (usually the name).
* All **configurable properties** of the object.
* **Parent object IDs** (typically names) all the way up to the root object.
* The **child classes** with a 1-to-1 relationship to the main object may be implemented within the same module.
    If the relationship is 1-to-many or many-to-many, the child object should generally have its own dedicated module. Some edge cases may deviate from this pattern.
* The state parameter:
    * `state: absent` to ensure the object does not exist
    * `state: present` to ensure the object and configurations exist; this is also the default
    * `state: query` to retrieve information about a specific object or all objects of the class

```python
def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        object_id=dict(type='str', aliases=['name']),
        object_prop1=dict(type='str'),
        object_prop2=dict(type='str', choices=['choice1', 'choice2', 'choice3']),
        object_prop3=dict(type='int'),
        parent_id=dict(type='str'),
        child_object_id=dict(type='str'),
        child_object_prop=dict(type='str'),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )
```

> [!NOTE]
> Avoid setting default values for configuration arguments unless the APIC explicitly applies them. Providing defaults may unintentionally modify the object during execution.

### Using the AnsibleModule object

This section creates an instance of AnsibleModule, passing in key attributes such as argument_spec, supports_check_mode, required_if, etc.

All ACI modules should support check mode, which allows Ansible to simulate a task without making any changes to the APIC. This helps users validate their playbooks safely.

The constructor takes the following arguments:
* `argument_spec`: The full set of module arguments, including shared and module-specific parameters.
* `supports_check_mode=True`: Enables check mode support (required in almost all modules in the ACI collection).
* `required_if`: Defines conditionally required arguments—i.e., arguments that are only mandatory under certain states such as present or absent.
* other parameters such as `required_one_of`, `required_together`, etc., can also be used to define complex dependencies between parameters, based on the module's requirements.

> [!TIP]
>  For more information on the AnsibleModule, refer to the [AnsibleModule documentation](https://docs.ansible.com/ansible/latest/dev_guide/developing_program_flow_modules.html#ansiblemodule).

```python
module = AnsibleModule(
    argument_spec=argument_spec,
    supports_check_mode=True,
    required_if=[
        ['state', 'absent', ['object_id', 'parent_id']],
        ['state', 'present', ['object_id', 'parent_id']],
    ],
)
```

Understanding required_if:
* The required_if parameter ensures that specific attributes (e.g., object_id, parent_id) are provided only when the module is creating (state: present) or deleting (state: absent) an object.
* These parameters are not required when the state is query, especially when performing a "query all" operation.
* If any of the required parameters are missing during present or absent states, Ansible will raise an error at runtime, prompting the user to supply the missing attributes.

This conditional requirement helps maintain flexibility while ensuring proper validation during object creation or removal.

### Mapping variable definition

After instantiating the AnsibleModule object (which is required for all modules), the next step is to extract parameter values from the playbook that correspond to the object's properties defined in the main() function. This is also the appropriate place to perform basic validations and string formatting or concatenation, as needed.

Once the AnsibleModule object is initialized as module, retrieve values from the module.params dictionary. Typically, only parameters related to the ACI object and its child configuration need to be extracted. Any necessary type checks or validations (e.g., capitalize the input or add special characters) should also be performed here.

```python
object_id = module.params.get('object_id')
object_prop1 = module.params.get('object_prop1')
object_prop2 = module.params.get('object_prop2')
object_prop3 = module.params.get('object_prop3')
if object_prop3 is not None and object_prop3 not in range(x, y):
    module.fail_json(msg='Valid object_prop3 values are between x and (y-1)')
child_object_id = module.params.get('child_object_id')
child_object_prop = module.params.get('child_object_prop')
state = module.params.get("state")
```

> [!NOTE]
> * In some cases, the APIC requires special characters (e.g., [, ], or -) in names, or uses internal metadata (e.g., "port_binding" attribute in aci_epg_to_domain module). Modules should handle formatting or concatenation of parameters internally to keep user input simple and intuitive.
> * Most type conversions and validations at this stage are minimal and are intended to ensure that properly formatted data is passed into subsequent API calls or logic.
> * Certain additional validations are only added when API response for these checks are not as expected.

### Using the ACIModule object

The ACIModule class manages most of the logic used by ACI modules. It extends the functionality of the AnsibleModule object, so the module instance must be passed during instantiation:

```python
aci = ACIModule(module)
```

The ACIModule includes 7 main methods commonly used across modules:

* construct_url
* get_existing
* payload
* get_diff
* post_config
* delete_config
* exit_json

The first 2 methods are used regardless of what value is passed to the `state` parameter.

#### Constructing URLs

The `construct_url()` method dynamically builds the REST API URL and query parameters for retrieving or configuring ACI objects. It supports multiple levels of the object hierarchy by accepting up to six optional subclass dictionaries and one list of child classes.

This method uses the root class (e.g., fvTenant) and optional subclass dictionaries to construct the full distinguished name (DN) of the object. It also applies filters and response modifiers.

* When the `state` is not `query`:The URL includes the full DN (base URL (to access the APIC) with the distinguished name of the object (to access the object)) of the object, and the response is typically limited to configuration data (config-only).
* When `state` is `query`, the URL and filter string used depend on which parameters are passed to the object. This method handles the complexity so that it is easier to add new modules and ensures that all modules are consistent in the type of data returned.

    * **Query specific object**: the URL is constructed to target a specific object within the module's class using its distinguished name. The filter string is typically not applied, allowing retrieval of the full object data. This approach simplifies module development by handling the URL construction dynamically and ensures consistent data retrieval for individual objects.

    * **Query all objects**: the URL is built to query all objects of the specified class. If a target filter is provided, it is applied as a query parameter to restrict the returned data to matching objects. This method manages the complexity of querying collections, making it easier to add new modules and maintain uniformity in the data returned across modules.

> [!IMPORTANT]
> The design goal for querying the objects, is to use the provided ID parameters to return the most specific data possible:
> * If no ID parameters are given, return all objects of the class.
> * If only some ID parameters are provided, return all objects that match those IDs.

> [!TIP]
>  For more information on the ACI REST APIs and how to construct URLs [ACI REST API Guide](https://www.cisco.com/c/en/us/td/docs/dcn/aci/apic/all/apic-rest-api-configuration-guide/cisco-apic-rest-api-configuration-guide-42x-and-later/m_using_the_rest_api.html).

The `construct_url()` method takes:
1.  **2 required arguments**:
    * **self** - passed automatically with the class instance
    * **root_class** - A dictionary consisting of `aci_class`, `aci_rn`, `target_filter`, and `module_object` keys
        + **aci_class**: The name of the class used by the APIC.
        + **aci_rn**: The relative name of the object.
        + **target_filter**: A dictionary with key-value pairs that make up the query string for selecting a subset of entries.
        + **module_object**: The particular object for this class.

Some modules, like `aci_tenant`, are the root class and so would not need to pass any additional arguments to the method.

2.  **7 optional arguments**:
    1. subclass_1 to subclass_6: Dictionaries similar to root_class
        * subclass_1 - A dictionary consisting of `aci_class`, `aci_rn`, `target_filter`, and `module_object` keys
        * subclass_2 - A dictionary consisting of `aci_class`, `aci_rn`, `target_filter`, and `module_object` keys
        * subclass_3 - A dictionary consisting of `aci_class`, `aci_rn`, `target_filter`, and `module_object` keys
        * subclass_4 - A dictionary consisting of `aci_class`, `aci_rn`, `target_filter`, and `module_object` keys
        * subclass_5 - A dictionary consisting of `aci_class`, `aci_rn`, `target_filter`, and `module_object` keys
        * subclass_6 - A dictionary consisting of `aci_class`, `aci_rn`, `target_filter`, and `module_object` keys
    2. child_classes: A list of supported child APIC class names (even if it is just one child class object)

> [!NOTE]
> * `aci_rn`: the relative name of the object, which is one section of the distinguished name (DN) with the ID of the specific argument. It should not contain the entire DN, as the method will automatically construct the full DN using the provided RNs of all arguments.
> * Refer to the modules aci_l3out_static_routes_nexthop for creation of object (ip:NexthopP) and aci_l3out_hsrp_secondary_vip for creation of object (hsrp:SecVip) for insights on how to use the `construct_url()` method.

Example:

```python
# If "dn" = "uni/tn-ansible_tenant/out-ansible_l3out/lnodep-ansible_node_profile/", then the construct_url() will be constructed as follows:

aci.construct_url(
    root_class=dict(
        aci_class='fvTenant',
        aci_rn='tn-{0}'.format(tenant),
        module_object=tenant,
        target_filter={'name': tenant}
    ),
    subclass_1=dict(
        aci_class='l3extOut',
        aci_rn='out-{0}'.format(l3out),
        module_object=l3out,
        target_filter={'name': l3out}
    ),
    subclass_2=dict(
        aci_class='l3extLNodeP',
        aci_rn='lnodep-{0}'.format(node_profile),
        module_object=node_profile,
        target_filter={'name': node_profile}
    )target_filter={'name': nexthop}
    )
)
```

> [!NOTE]
> Any requirements/changes for values of arguments (object,object_prop1, etc.) such as conversion to boolean, letter case, or formatting/validating the inputs must be done before the `construct_url()` method is called. This is because the method will use the values as they are passed in the task, and it will not perform any additional validation or conversion.

#### Getting the existing configuration

`aci.get_existing()` This retrieves the current APIC configuration based on the URL built in `construct_url()`.

* `state: present`: retrieves the configuration to use as a comparison against what was entered in the task. All values that are different from the existing values will be updated.
* `state: absent`: checks existing configuration, if the object exists before deletion.
* `state: query`: performs the query for the task and report back the existing data.

```python
aci.get_existing()
```

#### When state is present

When `state: present` a diff is performed between the task inputs and the existing configuration. If differences are found, the module sends a POST request to apply changes only the items that need to be updated. This ensures that only the necessary changes are made to the APIC configuration, minimizing disruption and maintaining consistency.

When state is present (executed when Adding an object and Updating an object), the module will:
1. Build the ACI payload using the `aci.payload()` method.
2. Perform a diff between the existing configuration and the proposed configuration using the `get_diff()` method.
3. Send the configuration changes to the APIC using the `post_config()` method.

##### Building the ACI payload

The `aci.payload()` method constructs a dictionary representing the proposed configuration for the ACI object. All parameter that is not provided a value in the task will be removed from the final dictionary — both for the main object and any child objects. Any parameters that do have values will be converted to strings and included in the resulting dictionary used for diff comparison.

* Parameters explicitly set to emptiness such as "" [] or {} based on the attribute type are excluded.
* If a non-default value already exists in the configuration and is not specified in the task, it will be preserved. For example, if a description is already set and the task omits it, the value will remain unchanged.

If a parameter was introduced in a newer version of the APIC, it should only be added to the payload when it has been assigned a value—this preserves backward compatibility.

**Parameters for `aci.payload()`**

This method accepts two required arguments and one optional argument (if the module handles child objects):

* `aci_class` is the Managed Object (MO) name for the object's class.
* `class_config` is the set of attributes of the aci class objects to be used as the payload for the POST request
    + The keys should match the names used by the APIC's MO.
    + The formatted values should be the values retrieved from `module.params` and modified if necessary to comply with the object model.
* `child_configs` is optional and is a list of child config dictionaries.
    + The child configs include the full child object dictionary, not just the attributes configuration portion.
    + The configuration portion is built the same way as the parent object.
* `annotation` is an optional string that can be used to add additional information to the object.
    + If annotation is a supported attribute for a module it will be populated in the payload of that respective module.
    + By default the value for annotation is set to `orchestrator:ansible` when not set by the users.


> [!NOTE]
> If any part of the class or child configuration depends on other parameter values, it is best to build these configurations ahead of time and then pass them to the aci.payload() function. This ensures the payload passed to aci.payload() is accurate and complete.

##### Performing the request

When state is present, a payload needs to be constructed which will be posted to APIC. Payload takes class_config and child_config. The class_config has the main attributes. If new attributes are added in new versions of APIC, that attribute will be added to class_config only if it is assigned a value.

> [!NOTE]
> `aci_rn` must **not** contain the DN of the individual class. It is `construct_url()`'s task to build the entire DN leading to the target object using the series of RNs in the root class and the subsequent subclasses.

##### Running the Diff

The `get_diff()` method compares the existing configuration with the new payload and returns a dictionary containing only the attributes that differ. It takes one required argument:

* `aci_class`: The MO name of the object being configured.

Replace `<managed object class>` with the appropriate MO class name for the object being configured.

You may also optionally pass:

* `required_properties` (optional): A dictionary of key-value pairs that should always be included in the resulting configuration, even if they are not part of the detected differences. This ensures critical properties are not inadvertently left out of updates and helps maintain consistent configurations.

This guarantees that key configuration elements are preserved in updates, even when no differences are detected in those fields.

##### Sending the Configuration

* `post_config()` method is used to make the POST request to the APIC by taking the result from `get_diff()`. This method:
    1. Requires no arguments.
    2. Handles check_mode internally.

Example code:

```python
if state == 'present':
    aci.payload(
        aci_class='<managed object class>',
        class_config=dict(
            name=object_id,
            prop1=object_prop1,
            prop2=object_prop2,
            prop3=object_prop3,
        ),
        child_configs=[
            dict(
                '<child managed object class>'=dict(
                    attributes=dict(
                        child_key=child_object_id,
                        child_prop=child_object_prop
                    ),
                ),
            ),
        ],
    )

    aci.get_diff(aci_class='<managed object class>')

    aci.post_config()
```

The end of the module does not change and generally remains as is. Therefore, the next sections until the end of the module can be used as it is.

#### When state is absent
If the task sets the state to absent, then the `delete_config()` method is all that is needed. This method does not take any arguments and handles check mode.

```python
elif state == 'absent':
        aci.delete_config()
```

#### Exiting the module
To have the module exit, call the ACIModule method `exit_json()`. This method automatically takes care of returning the common return values.

```python
aci.exit_json()


if __name__ == "__main__":
        main()
```

**Addition checks to perform after the module is created**:
* A newline should exist at the end of the file to ensure that the file ends with a newline character, which is a good practice and avoids sanity or black issues.
* Avoid using whitespaces or tabs at the end of lines, as this can lead to syntax errors or unexpected behavior.
* If the template from [docs/sample_module/aci_module_template.md](sample_module/aci_module_template.md) was used to create the new module, then remove all the comments in the file, except the copyright section at the top of the file. The comments in the template are only for reference and should not be included in the Pull Request for the new module.

## Testing the Module

Testing a module is crucial to ensure its reliability, correctness, and stability. It verifies that the module functions as intended across various scenarios, prevents regressions from new changes, and helps maintain a high-quality codebase.

Once the module is created, it should be tested using an Ansible playbook. This playbook (main.yml) is added under the collection directory at:
tests/integration/targets/<aci_module_name>/tasks/.
The playbook verifies the functionality of the module and ensures it behaves as expected.

The following tets are the performed on the module:

*   **Integration Test**: These tests validate the end-to-end functionality of the module within its intended environment, ensuring it interacts correctly with external systems like the APIC. They confirm that the module's code paths work as expected in a real-world scenario.
*   **Sanity Test**: Sanity tests check if the module adheres to coding standards and basic functionality across different Python and Ansible versions. They act as a quick health check to ensure fundamental aspects like documentation support and syntax are correct.
*   **Coverage Report**: This report identifies which parts of the module's code are executed by tests and which are not. It helps developers pinpoint untested areas, guiding them to write more comprehensive tests to improve code quality and reduce potential bugs.  

> For complete guidelines on how to write the playbook to test the module, refer to [Testing the modules documentation](testing_aci_modules.md).

### Additional checks before making a Pull Request

Before making a pull request, ensure that the following checks are performed:
1. The module is tested (Integration test, Sanity test, Black formatting).
2. The module has the necessary code coverage.
3. The commit message is **clear and concise**, following the [Ansible commit message guidelines](https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_general.html#commit-message-guidelines).
    * The commit message should always begin with `<commit_type>`, this helps in categorizing the changes made in the module.
    * The commit message must always end with the name of the module or playbook or docs that the changes are related to. 
    * Example: "`[<commit_type>]` Short description of the changes for the `aci_<ACI module name>` module."


    > The `<commit_type>` can be one of the following:
    > * `[minor_change]`: For adding small features or capabilities (e.g., adding a new module or attributes to an existing module)
    > * `[major_change]`: For changes made in the module which affects the existing behavior(breaking changes). (e.g., changes requiring testing the playbook or module updates)
    > * `[bugfix]`: For fixing bugs in the module (typically very small changes that don't add new functionality)
    > * `[ignore]`: For commits after the that do not affect the current test cases such as, code style changes, whitespace, typos, or documentation.

> [!IMPORTANT]
> It is recommended to make small PRs to ensure easier review and integration.


**Note**:

* [ACI Fundamentals: ACI Policy Model](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/1-x/aci-fundamentals/b_ACI-Fundamentals/b_ACI-Fundamentals_chapter_010001.html)
    A good introduction to the ACI object model.
* [APIC Management Information Model reference](https://developer.cisco.com/docs/apic-mim-ref/)
    Complete reference of the APIC object model.
* [APIC REST API Configuration Guide](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/2-x/rest_cfg/2_1_x/b_Cisco_APIC_REST_API_Configuration_Guide.html)
    Detailed guide on how the APIC REST API is designed and used, including many examples.  
 
