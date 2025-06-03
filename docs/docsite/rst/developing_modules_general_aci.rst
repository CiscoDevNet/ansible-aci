.. _aci_dev_guide:

****************************
Developing Cisco ACI modules
****************************
This is a developer guide for contributing modules to the Cisco ACI-Ansible collection. It is for developers who want to contribute code, fixes, or new modules to the collection. It will walk you through different steps and the expected conventions for contributions.

For more information about Cisco ACI, look at the :ref:`Cisco ACI user guide <aci_guide>`.

What's covered in this section:

.. contents::
   :depth: 3
   :local:

.. _aci_dev_guide_intro:

Introduction
============
The `cisco.aci collection <https://galaxy.ansible.com/cisco/aci>`_ already includes a large number of Cisco ACI modules; however, the ACI object model is huge, and covering all possible functionality would easily require more than 1,500 individual modules. Therefore, Cisco develops modules requested by people on a just-in-time basis.

If you need a specific functionality, you have three options:

- Open an issue using https://github.com/CiscoDevNet/ansible-aci/issues/new/choose so that Cisco developers can build, enhance, or fix the modules for you.
- Learn the ACI object model and use the low-level APIC REST API using the :ref:`aci_rest <aci_rest_module>` module.
- Contribute to Cisco's ansible-aci project by writing your own dedicated modules, proposing a fix or an enhancement, and being part of the Cisco ansible-aci community.

.. _aci_dev_guide_git:

In this guide, we're going to concentrate on the third option to show you how to build your own module, fix an issue, or improve an existing module and contribute it back to the ansible-aci project. The first step in the process is to retrieve the latest version of the ansible-aci collection code.
By retrieving the latest version, you will be able to modify existing code.

Fork, Clone and Branch
======================
The collection code is located in a git repository (https://github.com/CiscoDevNet/ansible-aci). You can directly clone this repository to retrieve the latest version of the code, but in order to later contribute your code back to the project, you will need to create a fork to be able to create a proper pull request.

**Fork**
   A fork is a copy of a repository that allows you to make changes to the repository without affecting the original project.
You can contribute your changes back to the original project by using Pull Requests from the forked repository.

  Let's create a fork of the repository.

* Go to: https://github.com/CiscoDevNet/ansible-aci
* Fork CiscoDevNet's **ansible-aci** repo by clicking the top right-hand corner fork button.

.. seealso::

   `_How to fork a repo: <https://docs.github.com/en/github/getting-started-with-github/fork-a-repo>`_

Now that we have forked our repository, let's clone the forked repository on our local machine.

**Clone**  
   Clone allows you to copy a repository to your local machine.

* Clone the forked repo by going to the terminal and enter the following command: 
.. code-block:: Blocks

   git clone https://github.com/<Forked Organization>/ansible-aci.git

**Naming Convention**
   "origin" is the default name for the first Git remote of a cloned repository. In this case, it represents your forked repo where you are going to make changes, commit, and push your code to GitHub.

* Verify the name of the Git remote of your forked repository by going to the terminal and enter the following command: 
.. code-block:: Blocks

   git remote -v

You should see in the output your repository listed after the name origin.
.. code-block:: Blocks

origin        https://github.com/<Forked Organization>/ansible-aci.git (fetch)
origin        https://github.com/<Forked Organization>/ansible-aci.git (push)

To be able to retrieve the latest changes made to the upstream project repo (CiscoDevNet/ansible-aci), we need to add it as a second Git remote. We recommend calling this second remote "upstream" and we will keep referring to it as upstream in the rest of the document.

* Add the upstream repo as a new Git remote:
.. code-block:: Blocks

   git remote add upstream https://github.com/CiscoDevNet/ansible-aci.git

Adding the main repository "upstream" is a one-time operation.
Now that we have added the upstream repo as a remote, we can make sure that our local master branch is up-to-date with the upstream repository.

* Update the local master branch from the upstream repository:
.. code-block:: Blocks

   git checkout master
   git pull upstream master

Now that our local master branch is up-to-date with the upstream repo, we can create a feature branch.

**Branch**
   Creating branches makes it easier to fix bugs, add new features, and integrate new versions after they have been tested in isolation. Master is the default branch of the local repository. Each time you need to make changes to a module or create a new module, we recommend that you create a new dedicated branch from master.

* Create a branch from master by using the following commands on the terminal:
.. code-block:: Blocks

   git checkout master
   git checkout -b <new-branch-name>
   git branch

You now have a clean branch of the latest master, where you can make all of your changes. By keeping your changes in a dedicated branch, you can keep the master branch clean and on track with the upstream master. This makes it easier to keep the local master branch updated without needing to merge code or rebase the master branch. As a best practice, we recommend that you do not commit changes to your local master branch but commit them to a dedicated feature branch.

Now that we have forked the repo, cloned it, and created a feature branch, let us look at how the repository and modules are structured.

.. _aci_dev_guide_module_structure:

ACI module structure
====================

Structure of the cisco.aci collection
-------------------------------------

The **ansible-aci** repository consists of directories and files as listed below:

.. code-block:: Blocks

      ansible-aci/
      ├─ plugins/
      │  ├─ modules/
      │  │  ├─ aci_l2out.py
      │  │  ├─ ...
      │  ├─ module_utils/
      │  │  ├─ aci.py
      │  ├─ doc_fragments/
      │  │  ├─ aci.py
      │  ├─ httpapi/
      │  │  ├─ aci.py
      ├─ tests/
      │  ├─ integration/
      │  │  ├─ inventory.networking
      │  │  ├─ targets/
      │  │  │  ├─ aci_l2out/
      │  │  │  │  ├─ tasks/
      │  │  │  │  │  ├─ main.yml
      │  │  │  ├─ .../
      │  ├─ sanity/
      │  │  ├─ requirements.txt
      │  ├─ unit/
      │  │  ├─ ...
      │  │  ├─ .../
      ├─ changelogs/
      │  ├─ changelog.yml
      │  ├─ config.yml
      ├─ meta/
      │  ├─ runtime.yml
      ├─ license
      ├─ galaxy.yml
      ├─ README
      ├─ requirements.txt

Let's briefly go through each file and its context.

**plugins**
   Consists of Python code that defines different functions and capabilities of the collection.

   The **modules** directory in plugins consists of Cisco ACI modules, and each module covers the functionality of an object in ACI. Any new module developed to manage an ACI object goes in this directory.

   The **module_utils** directory has the aci.py file, which serves as a library for the modules. Most modules in the collection borrow functions from this library. These functions help a module to access APIC, make requests to modify the configuration of an object in ACI, etc. This is where one would add any function to use across multiple modules.

   The **doc_fragments** directory has the aci.py file, which serves as a plugin and is used in each module's documentation. Every module has its own documentation section, but all the modules also share some common documentation elements, such as authentication details, notes: or seealso: entries. To avoid duplication of that information in each module's documentation block, it can be saved once in doc_fragment and used by all modules.

**tests** 
   This is where the different tests are defined. We run all sanity, unit, and integration tests on every code submission to the repository.

   The **integration** directory in **tests** consists of the **targets** directory, which has test directories for most of the modules present in our collection. Each module has its own test directory, and each directory is similar to an ansible role and contains a tasks directory, which contains a main.yml file. The main.yml file consists of tasks covering every functionality that a module provides. If the main.yml becomes too big, it can be split into multiple .yml files, and each of those can be imported into the main.yml file. Integration tests are run on every code submission to the repository. Every new module submission or bug fix or enhancement requires a test file or a change to an existing test file. This ensures that the code in our module is robust and foolproof.

   The **integration** directory also consists of the **inventory.networking** file, which defines the hosts, groups of hosts, and variables used by the integration tests role defined in the integration's targets directory.

**changelogs**
   This directory consists of a record of all the changes made to the project.

   The **changelog.yml** file contains a chronologically ordered list of the versions of the collection and the changes included in those versions. This file is used to generate the changelog.rst file. The changes usually include: major_changes, minor_changes, bugfixes, etc.

   The **config.yml** file contains variable names used by the **changelog.yml** file.

**galaxy.yml** 
   The **galaxy.yml** file is placed in the root directory of the collection. This file contains the metadata of the collection that is used to generate an ansible-aci collection object. It is also used for information in Ansible Galaxy.

Now that we understand the directory structure, let's look at how we use those files in those directories to build an ACI module.

Importing objects from Python libraries
---------------------------------------
The following imports are standard across ACI modules:

.. code-block:: python

    from ansible.module_utils.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
    from ansible.module_utils.basic import AnsibleModule

**ansible.module_utils.aci** is used to import the superclass ACIModule and the aci_argument_spec definition from the library aci.py in the module_utils directory we mentioned earlier. ACIModule is imported because it has basic functions to make API requests and other capabilities that allow our modules to manipulate objects. The aci.py library also contains a generic argument definition called **aci_argument_spec**. It is used by all the modules and allows them to accept shared parameters such as username and password.

Similarly, the AnsibleModule is imported, which contains common code for quickly building an Ansible module in Python.

Defining the argument_spec variable
-----------------------------------
The **argument_spec** variable is based on **aci_argument_spec** and allows a module to accept additional parameters from the user specific to the module.
The first line in the block adds the standard connection parameters to the module. After that, the next section will update the ``argument_spec`` dictionary with module-specific parameters. The module-specific parameters should include:

* the object_id (usually the name)
* the configurable properties of the object
* the object_id of each parent up to the root (usually the name)
* The child classes that have a 1-to-1 relationship with the main object don't need their own dedicated module and can be incorporated into the parent module. If the relationship is 1-to-many/many-to-many, this child class will need a dedicated module.
* the state

  + ``state: absent`` to ensure the object does not exist
  + ``state: present`` to ensure the object and configs exist; this is also the default
  + ``state: query`` to retrieve information about a specific object or all objects of the class

.. code-block:: python

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

.. note::  It is recommended not to provide default values for configuration arguments. Default values could cause unintended changes to the object.

Using the AnsibleModule object
------------------------------
The following section creates an instance of AnsibleModule and then adds to the constructor a series of properties such as the argument_spec. The module should support check-mode, which validates the working of a module without making any changes to the ACI object. The first attribute we pass to the constructor is ``argument_spec``; the second argument is ``supports_check_mode``. It is highly recommended that every module support check mode in this collection. The last element is required_if, which is used to specify conditional required attributes, and since these modules support querying the APIC for all objects of the module's class, the object/parent IDs should only be required if ``state: absent`` or ``state: present``.

.. code-block:: python

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['object_id', 'parent_id']],
            ['state', 'present', ['object_id', 'parent_id']],
        ],
    )

Mapping variable definition
---------------------------
Once the AnsibleModule object has been instantiated as module, the necessary parameter values should be extracted from the ``module.params`` dictionary and all additional data should be validated. Usually, the only parameters that need to be extracted are those related to the ACI object configuration and its child configuration. If you have integer objects that you would like to validate, then the validation should be done here.

.. code-block:: python

    object_id = object_id
    object_prop1 = module.params['object_prop1']
    object_prop2 = module.params['object_prop2']
    object_prop3 = module.params['object_prop3']
    if object_prop3 is not None and object_prop3 not in range(x, y):
        module.fail_json(msg='Valid object_prop3 values are between x and (y-1)')
    child_object_id = module.params['child_object_id']
    child_object_prop = module.params['child_object_prop']
    state = module.params['state']

.. note:: Sometimes the APIC will require special characters ([, ], and -) or will use object metadata in the name ("vlanns" for VLAN pools); the module should handle adding special characters or joining multiple parameters in order to keep expected inputs simple.

Using the ACIModule object
--------------------------
The ACIModule class handles most of the logic for the ACI modules. The ACIModule extends the functionality of the AnsibleModule object, so the module instance must be passed into the class instantiation.

.. code-block:: python

    aci = ACIModule(module)

The ACIModule has six main methods that are used by most modules in the collection:

* construct_url
* get_existing
* payload
* get_diff
* post_config
* delete_config

The first two methods are used regardless of what value is passed to the ``state`` parameter.


Constructing URLs
^^^^^^^^^^^^^^^^^
The ``construct_url()`` method is used to dynamically build the appropriate URL to interact with the object, as well as the appropriate filter string that should be appended to the URL to filter the results.

* When the ``state`` is not ``query``, the URL is the base URL to access the APIC plus the distinguished name to access the object. The filter string will restrict the returned data to just the configuration data.
* When ``state`` is ``query``, the URL and filter string used depend on which parameters are passed to the object. This method handles the complexity so that it is easier to add new modules and ensures that all modules are consistent in the type of data returned.

.. note:: Our design goal is to take all ID parameters that have values and return the most specific data possible. If you do not supply any ID parameters to the task, then all objects of the class will be returned. If your task does consist of ID parameters used, then the data for the specific object is returned. If a partial set of ID parameters is passed, then the module will use the IDs that are passed to build the URL and filter strings appropriately.

The ``construct_url()`` method takes two required arguments:

* **self** - passed automatically with the class instance
* **root_class** - A dictionary consisting of ``aci_class``, ``aci_rn``, ``target_filter``, and ``module_object`` keys

  + **aci_class**: The name of the class used by the APIC, for example ``fvTenant``

  + **aci_rn**: The relative name of the object, for example ``tn-ACME``

  + **target_filter**: A dictionary with key-value pairs that make up the query string for selecting a subset of entries, for example ``{'name': 'ACME'}``

  + **module_object**: The particular object for this class, for example ``ACME``

Example:

.. code-block:: python

    aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            target_filter={'name': tenant},
            module_object=tenant,
        ),
    )

Some modules, like ``aci_tenant``, are the root class and so would not need to pass any additional arguments to the method.

The ``construct_url()`` method takes six optional arguments; the first five imitate the root class as described above and the rest are for child objects:

* subclass_1 - A dictionary consisting of ``aci_class``, ``aci_rn``, ``target_filter``, and ``module_object`` keys

  + Example: Application Profile Class (AP)

* subclass_2 - A dictionary consisting of ``aci_class``, ``aci_rn``, ``target_filter``, and ``module_object`` keys

  + Example: End Point Group (EPG)

* subclass_3 - A dictionary consisting of ``aci_class``, ``aci_rn``, ``target_filter``, and ``module_object`` keys

  + Example: Binding a Contract to an EPG

* subclass_4 - A dictionary consisting of ``aci_class``, ``aci_rn``, ``target_filter``, and ``module_object`` keys

  + Example: Managing External Subnet objects (l3ext:ipRouteP)

* subclass_5 - A dictionary consisting of ``aci_class``, ``aci_rn``, ``target_filter``, and ``module_object`` keys

  + Example: Managing nexthops for static routes.

* child_classes - The list of APIC names for the child classes supported by the modules.

  + This is a list, even if it contains only one item
  + These are the unfriendly names used by the APIC
  + These are used to limit the returned child_classes when possible
  + Example: ``child_classes=['fvRsBDSubnetToProfile', 'fvRsNdPfxPol']``

Example:

.. code-block:: python

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
           ),
           subclass_3=dict(
               aci_class='l3extRsNodeL3OutAtt',
               aci_rn='rsnodeL3OutAtt-[{0}]'.format(node_tdn),
               module_object=node_tdn,
               target_filter={'name': node_tdn}
           ),
           subclass_4=dict(
               aci_class='ipRouteP',
               aci_rn='rt-[{0}]'.format(prefix),
               module_object=prefix,
               target_filter={'name': prefix}
           ),
           subclass_5=dict(
               aci_class='ipNexthopP',
               aci_rn='nh-[{0}]'.format(nexthop),
               module_object=nexthop,
               target_filter={'name': nexthop}
           )
       )

.. note:: rn is one section of dn, with the ID of the specific argument. Do not put the entire dn in the **aci_rn** of each argument. The method automatically constructs the dn using the rn of all the arguments above.

Getting the existing configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Once the URL and filter string have been built, the module is ready to retrieve the existing configuration for the object:

* ``state: present`` retrieves the configuration to use as a comparison against what was entered in the task. All values that are different from the existing values will be updated.
* ``state: absent`` uses the existing configuration to see if the item exists and needs to be deleted.
* ``state: query`` uses this to perform the query for the task and report back the existing data.

.. code-block:: python

    aci.get_existing()

When state is present
^^^^^^^^^^^^^^^^^^^^^
When ``state: present``, the module needs to perform a diff against the existing configuration and the task entries. If any value needs to be updated, the module will make a POST request with only the items that need to be updated. In other words, the payload is built with the expected configuration and this is compared with the existing configuration that we retrieved. If we need to make a change, then we'll push the changed configuration to APIC. Some modules have children that are in a 1-to-1 relationship with another object; for these cases, the module can be used to manage the child objects.

Building the ACI payload
""""""""""""""""""""""""
The ``aci.payload()`` method is used to build a dictionary of the proposed object configuration. All parameters that were not provided a value in the task will be removed from the dictionary (both for the object and its children). Any parameter that does have a value will be converted to a string and added to the final dictionary object that will be used for comparison against the existing configuration.

We remove the values of parameters that are empty. If there is a previous configuration for the value that is non-default, then the parameter will not be modified if we do not reset it. For example, if the description is set to something and then we run it again with no description, it will not change it to the default.

If parameters of the payload have been added in a recent version, we recommend adding the new parameters to the payload when the parameter is assigned a value. This is done to maintain backward compatibility.

The ``aci.payload()`` method takes two required arguments and one optional argument, depending on whether the module manages child objects.

* ``aci_class`` is the APIC name for the object's class, for example ``aci_class='fvBD'``
* ``class_config`` is the set of attributes of the aci class objects to be used as the payload for the POST request

  + The keys should match the names used by the APIC.
  + The formatted values should be the values retrieved from ``module.params`` and modified if necessary to comply with the object model.

* ``child_configs`` is optional and is a list of child config dictionaries.

  + The child configs include the full child object dictionary, not just the attributes configuration portion.
  + The configuration portion is built the same way as the object.

.. code-block:: python

    aci.payload(
        aci_class=aci_class,
        class_config=dict(
            name=bd,
            descr=description,
            type=bd_type,
        ),
        child_configs=[
            dict(
                fvRsCtx=dict(
                    attributes=dict(
                        tnFvCtxName=vrf
                    ),
                ),
            ),
        ],
    )

Sometimes the class config or child config depends on the parameter itself. If this is the case, we recommend creating them before building the aci payload.

Performing the request
""""""""""""""""""""""
The ``get_diff()`` method is used to perform the diff and takes only one required argument, ``aci_class``. In other words, it is used to make a comparison between the ACI payload and the existing configuration, and only create what's actually needed between the two.
Example: ``aci.get_diff(aci_class='fvBD')``

The ``post_config()`` method is used to make the POST request to the APIC by taking the result from ``get_diff()``. This method doesn't take any arguments and handles check mode. Example: ``aci.post_config()``.

Example code
""""""""""""
.. code-block:: text

    if state == 'present':
        aci.payload(
            aci_class='<object APIC class>',
            class_config=dict(
                name=object_id,
                prop1=object_prop1,
                prop2=object_prop2,
                prop3=object_prop3,
            ),
            child_configs=[
                dict(
                    '<child APIC class>'=dict(
                        attributes=dict(
                            child_key=child_object_id,
                            child_prop=child_object_prop
                        ),
                    ),
                ),
            ],
        )

        aci.get_diff(aci_class='<object APIC class>')

        aci.post_config()


When state is absent
^^^^^^^^^^^^^^^^^^^^
If the task sets the state to absent, then the ``delete_config()`` method is all that is needed. This method does not take any arguments and handles check mode.

.. code-block:: text

        elif state == 'absent':
            aci.delete_config()


Exiting the module
^^^^^^^^^^^^^^^^^^
To have the module exit, call the ACIModule method ``exit_json()``. This method automatically takes care of returning the common return values for you.

.. code-block:: text

        aci.exit_json()

    if __name__ == '__main__':
        main()

Documentation Section
---------------------
All the parameters defined in the argument_spec, like the object_id, configurable properties of the object, parent object_id, state, etc., need to be documented in the same file as the module. The format of documentation is shown below:

.. code-block:: yaml

   DOCUMENTATION = r'''
   ---
   module: aci_<name_of_module>
   short_description: Short description of the module being created (config:<name_of_class>)
   description:
   - Functionality one
   - Functionality two
   options:
     object_id:
       description:
       - Description of object
       type: Data type of object eg. 'str'
       aliases: [ Alternate name of the object ]
     object_prop1:
       description:
       - Description of property one
       type: Property's data type eg. 'int'
       choices: [ choice one, choice two ]
     object_prop2:
       description:
       - Description of property two
       type: Property's data type eg. 'bool'
     state:
       description:
       - Use C(present) or C(absent) for adding or removing.
       - Use C(query) for listing an object or multiple objects.
       type: str
       choices: [ absent, present, query ]
       default: present
   extends_documentation_fragment:
   - cisco.aci.aci

Examples Section
----------------
The examples section must consist of Ansible tasks which can be used as a reference to build playbooks. The format of this section is shown below:

.. code-block:: yaml

   EXAMPLES = r'''
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

   - name: Remove an object
     cisco.aci.aci_<name_of_module>:
       host: apic
       username: admin
       password: SomeSecretePassword
       object_id: id
       object_prop1: prop1
       object_prop2: prop2
       state: absent
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
   '''
.. note:: Make sure to test the examples since people generally copy and paste examples to use the module.

Return Section
----------------
The RETURN section is used in every module and has the same content, so copy and paste it from any module.

.. code-block:: python

   RETURN = r'''
            current:
              description: The existing configuration from the APIC after the module has finished
              returned: success
              type: list
              sample:
                [
                    {
                        "fvTenant": {
                            "attributes": {
                                "descr": "Production environment",
                                "dn": "uni/tn-production",
                                "name": "production",
                                "nameAlias": "",
                                "ownerKey": "",
                                "ownerTag": ""
                            }
                        }
                    }
                ]
            error:
              description: The error information as returned from the APIC
              returned: failure
              type: dict
              sample:
                {
                    "code": "122",
                    "text": "unknown managed object class foo"
                }
            raw:
              description: The raw output returned by the APIC REST API (xml or json)
              returned: parse error
              type: str
              sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class "/></imdata>'
            sent:
              description: The actual/minimal configuration pushed to the APIC
              returned: info
              type: list
              sample:
                {
                    "fvTenant": {
                        "attributes": {
                            "descr": "Production environment"
                        }
                    }
                }
            previous:
              description: The original configuration from the APIC before the module has started
              returned: info
              type: list
              sample:
                [
                    {
                        "fvTenant": {
                            "attributes": {
                                "descr": "Production",
                                "dn": "uni/tn-production",
                                "name": "production",
                                "nameAlias": "",
                                "ownerKey": "",
                                "ownerTag": ""
                            }
                        }
                    }
                ]
            proposed:
              description: The assembled configuration from the user-provided parameters
              returned: info
              type: dict
              sample:
                {
                    "fvTenant": {
                        "attributes": {
                            "descr": "Production environment",
                            "name": "production"
                        }
                    }
                }
            filter_string:
              description: The filter string used for the request
              returned: failure or debug
              type: str
              sample: ?rsp-prop-include=config-only
            method:
              description: The HTTP method used for the request to the APIC
              returned: failure or debug
              type: str
              sample: POST
            response:
              description: The HTTP response from the APIC
              returned: failure or debug
              type: str
              sample: OK (30 bytes)
            status:
              description: The HTTP status from the APIC
              returned: failure or debug
              type: int
              sample: 200
            url:
              description: The HTTP url used for the request to the APIC
              returned: failure or debug
              type: str
              sample: https://10.11.12.13/api/mo/uni/tn-production.json
            '''

Example Module
--------------
The following example consists of Documentation, Examples and Module Sections discussed above. All these sections must be present in a single file: **aci_<aci-module-name>.py** which goes inside the **modules** directory.

.. code-block:: python

      #!/usr/bin/python
      # -*- coding: utf-8 -*-

      # Copyright: (c) <year>, <Name> (@<github id>)
      # GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

      from __future__ import absolute_import, division, print_function
      __metaclass__ = type

      ANSIBLE_METADATA = {'metadata_version': '1.1',
                          'status': ['preview'],
                          'supported_by': 'community'}

      DOCUMENTATION = r'''
      ---
      module: aci_l2out
      short_description: Manage Layer2 Out (L2Out) objects.
      description:
      - Manage Layer2 Out configuration on Cisco ACI fabrics.
      options:
        tenant:
          description:
          - Name of an existing tenant.
          type: str
        l2out:
          description:
          - The name of outer layer2.
          type: str
          aliases: [ 'name' ]
        description:
          description:
          - Description for the L2Out.
          type: str
        bd:
          description:
          - Name of the Bridge domain which is associated with the L2Out.
          type: str
        domain:
          description:
          - Name of the external L2 Domain that is being associated with L2Out.
          type: str
        vlan:
          description:
          - The VLAN which is being associated with the L2Out.
          type: int
        state:
          description:
          - Use C(present) or C(absent) for adding or removing.
          - Use C(query) for listing an object or multiple objects.
          type: str
          choices: [ absent, present, query ]
          default: present
        name_alias:
          description:
          - The alias for the current object. This relates to the nameAlias field in ACI.
          type: str
      extends_documentation_fragment:
      - cisco.aci.aci

      notes:
      - The C(tenant) must exist before using this module in your playbook.
        The M(cisco.aci.aci_tenant) modules can be used for this.
      seealso:
      - name: APIC Management Information Model reference
        description: More information about the internal APIC class B(fvTenant).
        link: https://developer.cisco.com/docs/apic-mim-ref/
      author:
      - <Author's Name> (@<github id>)
      '''

      EXAMPLES = r'''
      - name: Add a new L2Out
        cisco.aci.aci_l2out:
          host: apic
          username: admin
          password: SomeSecretePassword
          tenant: Auto-Demo
          l2out: l2out
          description: via Ansible
          bd: bd1
          domain: l2Dom
          vlan: 3200
          state: present
          delegate_to: localhost

      - name: Remove an L2Out
        cisco.aci.aci_l2out:
          host: apic
          username: admin
          password: SomeSecretePassword
          tenant: Auto-Demo
          l2out: l2out
          state: absent
          delegate_to: localhost

      - name: Query an L2Out
        cisco.aci.aci_l2out:
          host: apic
          username: admin
          password: SomeSecretePassword
          tenant: Auto-Demo
          l2out: l2out
          state: query
          delegate_to: localhost
          register: query_result

      - name: Query all L2Outs in a specific tenant
        cisco.aci.aci_l2out:
          host: apic
          username: admin
          password: SomeSecretePassword
          tenant: Auto-Demo
          state: query
          delegate_to: localhost
          register: query_result
      '''

      RETURN = r'''
         current:
           description: The existing configuration from the APIC after the module has finished
           returned: success
           type: list
           sample:
             [
                 {
                     "fvTenant": {
                         "attributes": {
                             "descr": "Production environment",
                             "dn": "uni/tn-production",
                             "name": "production",
                             "nameAlias": "",
                             "ownerKey": "",
                             "ownerTag": ""
                         }
                     }
                 }
             ]
         error:
           description: The error information as returned from the APIC
           returned: failure
           type: dict
           sample:
             {
                 "code": "122",
                 "text": "unknown managed object class foo"
             }
         raw:
           description: The raw output returned by the APIC REST API (xml or json)
           returned: parse error
           type: str
           sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class "/></imdata>'
         sent:
           description: The actual/minimal configuration pushed to the APIC
           returned: info
           type: list
           sample:
             {
                 "fvTenant": {
                     "attributes": {
                         "descr": "Production environment"
                     }
                 }
             }
         previous:
           description: The original configuration from the APIC before the module has started
           returned: info
           type: list
           sample:
             [
                 {
                     "fvTenant": {
                         "attributes": {
                             "descr": "Production",
                             "dn": "uni/tn-production",
                             "name": "production",
                             "nameAlias": "",
                             "ownerKey": "",
                             "ownerTag": ""
                         }
                     }
                 }
             ]
         proposed:
           description: The assembled configuration from the user-provided parameters
           returned: info
           type: dict
           sample:
             {
                 "fvTenant": {
                     "attributes": {
                         "descr": "Production environment",
                         "name": "production"
                     }
                 }
             }
         filter_string:
           description: The filter string used for the request
           returned: failure or debug
           type: str
           sample: ?rsp-prop-include=config-only
         method:
           description: The HTTP method used for the request to the APIC
           returned: failure or debug
           type: str
           sample: POST
         response:
           description: The HTTP response from the APIC
           returned: failure or debug
           type: str
           sample: OK (30 bytes)
         status:
           description: The HTTP status from the APIC
           returned: failure or debug
           type: int
           sample: 200
         url:
           description: The HTTP url used for the request to the APIC
           returned: failure or debug
           type: str
           sample: https://10.11.12.13/api/mo/uni/tn-production.json
         '''

      from ansible.module_utils.basic import AnsibleModule
      from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec


      def main():
          argument_spec = aci_argument_spec()
          argument_spec.update(
              bd=dict(type='str'),
              l2out=dict(type='str', aliases=['name']),
              domain=dict(type='str'),
              vlan=dict(type='int'),
              description=dict(type='str'),
              state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
              tenant=dict(type='str'),
              name_alias=dict(type='str'),
          )

          module = AnsibleModule(
              argument_spec=argument_spec,
              supports_check_mode=True,
              required_if=[
                  ['state', 'absent', ['l2out', 'tenant']],
                  ['state', 'present', ['bd', 'l2out', 'tenant', 'domain', 'vlan']],
              ],
          )

          bd = module.params.get('bd')
          l2out = module.params.get('l2out')
          description = module.params.get('description')
          domain = module.params.get('domain')
          vlan = module.params.get('vlan')
          state = module.params.get('state')
          tenant = module.params.get('tenant')
          name_alias = module.params.get('name_alias')
          child_classes = ['l2extRsEBd', 'l2extRsL2DomAtt', 'l2extLNodeP']

          aci = ACIModule(module)
          aci.construct_url(
              root_class=dict(
                  aci_class='fvTenant',
                  aci_rn='tn-{0}'.format(tenant),
                  module_object=tenant,
                  target_filter={'name': tenant},
              ),
              subclass_1=dict(
                  aci_class='l2extOut',
                  aci_rn='l2out-{0}'.format(l2out),
                  module_object=l2out,
                  target_filter={'name': l2out},
              ),
              child_classes=child_classes,
          )

          aci.get_existing()

          if state == 'present':
              child_configs = [
                  dict(
                      l2extRsL2DomAtt=dict(
                          attributes=dict(
                              tDn='uni/l2dom-{0}'.format(domain)
                          )
                      )
                  ),
                  dict(
                      l2extRsEBd=dict(
                          attributes=dict(
                              tnFvBDName=bd, encap='vlan-{0}'.format(vlan)
                          )
                      )
                  )
              ]

              aci.payload(
                  aci_class='l2extOut',
                  class_config=dict(
                      name=l2out,
                      descr=description,
                      dn='uni/tn-{0}/l2out-{1}'.format(tenant, l2out),
                      nameAlias=name_alias
                  ),
                  child_configs=child_configs,
              )

              aci.get_diff(aci_class='l2extOut')

              aci.post_config()

          elif state == 'absent':
              aci.delete_config()

          aci.exit_json()


      if __name__ == "__main__":
          main()

Building Your Own Module
------------------------

Now that we have explained and seen the components of the ACI module structure, let us build our own module. The following section shows a basic and practical approach to building a module with the help of an existing module. This approach makes it easier to create a new module without having to write everything from scratch.

The purpose of this section is to show how to build a module based on an existing module. This is done by selecting a module that is similar to the one you want to build in order to reduce the number of changes needed. For this, you can either take the parent object and append the attributes required for your module. If this is not possible, use a sibling object or an object at the same level.

Let's build a module for l3out static routes using the existing module for l3out logical node:
aci_l3out_logical_node -> aci_l3out_static_routes

1. In the modules directory located in the plugins directory of the collection, select and copy the contents of the aci_l3out_logical_node module, paste it into a file, and save it in .py format. We name this file aci_l3out_static_routes. To create a name for the new module, look at the names of other modules in the directory for consistency.

2. Change the copyright section by adding your name and email address: # Copyright: (c) <year>, <Name> (<email>) below:

.. code-block:: python

   #!/usr/bin/python
   # -*- coding: utf-8 -*-

   # Copyright: (c) <year>, <Name> (<email>)
   # GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

   from __future__ import absolute_import, division, print_function
   __metaclass__ = type

   ANSIBLE_METADATA = {
       'metadata_version': '1.1',
       'status': ['preview'],
       'supported_by': 'community'
   }

3. In the documentation section, we begin by changing the name of the module, its short description and the description of the functions being performed on the object. The description of the module must be followed by the options which is a list of attributes and each attribute should include the name, description, data type, aliases(if applicable), choices(if applicable) and default(if applicable) of all the parameters that will be consumed by the object. For our aci_l3out_static_routes module this would include additon of new options to aci_l3out_logical_node module that include description, prefix, track_policy, preference, bfd and removal of router_id and router_id_as_loopback from aci_l3out_logical_node module. 

The changes made are shown below:

.. code-block:: yaml

      DOCUMENTATION = r'''
      ---
      module: aci_l3out_logical_node
      module: aci_l3out_static_routes
      short_description: Manage Layer 3 Outside (L3Out) logical node profile nodes (l3ext:RsNodeL3OutAtt) 
      short_description: Manage Static routes object (l3ext:ipRouteP)
      description:
      - Bind nodes to node profiles on Cisco ACI fabrics.
       description:
      - Manage External Subnet objects (l3ext:ipRouteP).
      options:
        description:
          description:
          - The description for the static routes.
          type: str
          aliases: [ descr ]
        tenant:
          description:
          - Name of an existing tenant.
          type: str
          aliases: [ tenant_name ]
        l3out:
          description:
          - Name of an existing L3Out.
          type: str
          aliases: [ l3out_name ]
        logical_node:
          description:
          - Name of an existing logical node profile.
          type: str
          aliases: [ node_profile, node_profile_name ]
        pod_id:
          description:
          - Existing podId.
          type: int
        node_id:
          description:
          - Existing nodeId.
          type: int
        prefix:
          description:
          - Configure IP and next hop IP for the routed outside network.
          type: str
          aliases: [ route ]
        track_policy:
          description:
          - Relation definition for static route to TrackList.
          type: str
        preference:
          description:
          - Administrative preference value for the route.
          type: int
        bfd:
          description:
          - Determines if bfd is required for route control.
          - The APIC defaults to C(null) when unset during creation.
          type: str
          choices: [ bfd, null ]
        state:
          description:
          - Use C(present) or C(absent) for adding or removing.
          - Use C(query) for listing an object or multiple objects.
          type: str
          choices: [ absent, present, query ]
          default: present
        name_alias:
          description:
          - The alias for the current object. This relates to the nameAlias field in ACI.
          type: str
      extends_documentation_fragment:
      - cisco.aci.aci
      
4. The options are followed by notes, which usually contain any dependencies of the module being created with the parent modules that exist in the collection. We also include a "see also" section, which provides a link to the class being used in the module, followed by the author's name and GitHub ID as shown below.

.. code-block:: yaml

      notes:
      - The C(tenant), C(l3out), C(logical_node), C(fabric_node) and C(prefix) used must exist before using this module in your playbook.
        The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_l3out) modules can be used for this.
      seealso:
      - module: cisco.aci.aci_tenant
      - module: cisco.aci.aci_l3out
      - name: APIC Management Information Model reference
        description: More information about the internal APIC class B(l3ext:Out).
        link: https://developer.cisco.com/docs/apic-mim-ref/
      author:
      - <author's name> (<author's github id>)
      '''

5. Our documentation section is complete. Next, we skim through the examples section of the copied module and make changes to it by adding the necessary parameters to all the examples. Please note that removing and querying an object will only contain the object name and no object parameters. "Query All" will not have any parameters, ensuring that all the objects of the class being worked upon are returned.

.. code-block:: yaml

   EXAMPLES = r'''
   - name: Create static routes
     cisco.aci.aci_l3out_static_routes:
       host: apic
       username: admin
       password: SomeSecretPassword
       tenant: tenantName
       l3out: l3out
       logical_node: nodeName
       node_id: 101
       pod_id: 1
       prefix: 10.10.0.0/16
     delegate_to: localhost

   - name: Delete static routes
     cisco.aci.aci_l3out_static_routes:
       host: apic
       username: admin
       password: SomeSecretPassword
       tenant: tenantName
       l3out: l3out
       logical_node: nodeName
       node_id: 101
       pod_id: 1
       prefix: 10.10.0.0/16
     delegate_to: localhost

   - name: Query for a specific MO under l3out
     cisco.aci.aci_l3out_static_routes:
       host: apic
       username: admin
       password: SomeSecretPassword
       tenant: tenantName
       l3out: l3out
       logical_node: nodeName
       node_id: 101
       pod_id: 1
       prefix: 10.10.0.0/16
     delegate_to: localhost

   - name: Query for all static routes
     cisco.aci.aci_l3out_static_routes:
       host: apic
       username: admin
       password: SomeSecretPassword
       tenant: production
       state: query
     delegate_to: localhost
   '''

6. We leave the Return section as is and then proceed to the main code.

.. code-block:: yaml

   RETURN = r'''
   current:
     description: The existing configuration from the APIC after the module has finished
     returned: success
     type: list
     sample:
       [
           {
               "fvTenant": {
                   "attributes": {
                       "descr": "Production environment",
                       "dn": "uni/tn-production",
                       "name": "production",
                       "nameAlias": "",
                       "ownerKey": "",
                       "ownerTag": ""
                   }
               }
           }
       ]
   error:
     description: The error information as returned from the APIC
     returned: failure
     type: dict
     sample:
       {
           "code": "122",
           "text": "unknown managed object class foo"
       }
   raw:
     description: The raw output returned by the APIC REST API (xml or json)
     returned: parse error
     type: str
     sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class foo"/></imdata>'
   sent:
     description: The actual/minimal configuration pushed to the APIC
     returned: info
     type: list
     sample:
       {
           "fvTenant": {
               "attributes": {
                   "descr": "Production environment"
               }
           }
       }
   previous:
     description: The original configuration from the APIC before the module has started
     returned: info
     type: list
     sample:
       [
           {
               "fvTenant": {
                   "attributes": {
                       "descr": "Production",
                       "dn": "uni/tn-production",
                       "name": "production",
                       "nameAlias": "",
                       "ownerKey": "",
                       "ownerTag": ""
                   }
               }
           }
       ]
   proposed:
     description: The assembled configuration from the user-provided parameters
     returned: info
     type: dict
     sample:
       {
           "fvTenant": {
               "attributes": {
                   "descr": "Production environment",
                   "name": "production"
               }
           }
       }
   filter_string:
     description: The filter string used for the request
     returned: failure or debug
     type: str
     sample: ?rsp-prop-include=config-only
   method:
     description: The HTTP method used for the request to the APIC
     returned: failure or debug
     type: str
     sample: POST
   response:
     description: The HTTP response from the APIC
     returned: failure or debug
     type: str
     sample: OK (30 bytes)
   status:
     description: The HTTP status from the APIC
     returned: failure or debug
     type: int
     sample: 200
   url:
     description: The HTTP url used for the request to the APIC
     returned: failure or debug
     type: str
     sample: https://10.11.12.13/api/mo/uni/tn-production.json
   '''


7. The following import section is generally left untouched, but if you add a shared method in the library, you might need to import it here.

.. code-block:: python

   from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
   from ansible.module_utils.basic import AnsibleModule

8. In the main function, the argument_spec variable defines all the arguments necessary for this module and is based on aci_argument_spec. We add all the arguments we defined previously in the documentation section to this variable. In our case, we would add description, prefix, track_policy, preference, and bfd to the section below and remove router_id and router_id_as_loopback.

.. code-block:: python

     def main():
       argument_spec = aci_argument_spec()
       argument_spec.update(
           tenant=dict(type='str', aliases=['tenant_name']),  
           l3out=dict(type='str', aliases=['l3out_name']),  
           logical_node=dict(type='str', aliases=['node_profile', 'node_profile_name']),  
           pod_id=dict(type='int'),
           node_id=dict(type='int'),
           prefix=dict(type='str', aliases=['route']),
           track_policy=dict(type='str'),
           preference=dict(type='int'),
           bfd=dict(type='str', choices=['bfd', None]),
           description=dict(type='str', aliases=['descr']),
           state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
           name_alias=dict(type='str'),
    )

9. The required_if variable has the following arguments. We do not set the arguments below for all states because we need to use "Query All," which doesn't need those arguments. However, we still need the user to fill in the arguments when they want to create or delete something. That's why we put them in required_if, which allows us to specify what attributes are required when state is present or absent. If any of the attributes below —'prefix', 'node_id', 'pod_id', 'logical_node', 'l3out', and 'tenant' are missing in the task that adds or deletes the object in the playbook, Ansible will immediately complain that the attributes are missing.

.. code-block:: python

      module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'present', ['prefix', 'node_id', 'pod_id', 'logical_node', 'l3out', 'tenant']],
            ['state', 'absent', ['prefix', 'node_id', 'pod_id', 'logical_node', 'l3out', 'tenant']],
        ],
    )

.. code-block:: python

   aci = ACIModule(module)

10. The above instantiation (required for all modules) is followed by code that is used to get attributes from the playbook that correspond to all the properties of objects defined in the main() function above. This is also where validations and string concatenations are done. We have assigned fabric_node with a part of rn using string concatenation. This is done to make certain operations easier, which are used later in the code. The child class 'ipNexthopP', which is in a 1-to-1 relationship with the class 'ipRouteP', is in a list. Child classes that are dependent on an attribute are only required when the attribute is defined, as seen below with track_policy. The child class 'ipRsRouteTrack' is appended to the list, which already has 'ipNexthopP'.

.. code-block:: python

    tenant = module.params.get('tenant')
    l3out = module.params.get('l3out')
    logical_node = module.params.get('logical_node')
    node_id = module.params.get('node_id')
    pod_id = module.params.get('pod_id')
    prefix = module.params.get('prefix')
    track_policy = module.params.get('track_policy')
    preference = module.params.get('preference')
    bfd = module.params.get('bfd')
    description = module.params.get('description')
    state = module.params.get('state')
    name_alias = module.params.get('name_alias')

    fabric_node = 'topology/pod-{0}/node-{1}'.format(pod_id, node_id)
    child_classes = ['ipNexthopP']
    if track_policy is not None:
       child_classes.append('ipRsRouteTrack')

11. The following section constructs a filter to target a set of entries that match certain criteria at the level of the target DN and in the subtree below it. The construct_url function below is used to build the appropriate DN by using the tenant as the root class and other subsequent subclasses up to 'ipRouteP'.

Note - aci_rn must not contain the DN of the individual class. It is construct_url()'s task to build the entire DN leading to the target object using the series of RNs in the root class and the subsequent subclasses.

.. code-block:: python

      aci.construct_url(
        root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant},
        ),
        subclass_1=dict(
            aci_class='l3extOut',
            aci_rn='out-{0}'.format(l3out),
            module_object=l3out,
            target_filter={'name': l3out},
        ),
        subclass_2=dict(
            aci_class='l3extLNodeP',
            aci_rn='lnodep-{0}'.format(logical_node),
            module_object=logical_node,
            target_filter={'name': logical_node},
        ),
        subclass_3=dict(
            aci_class='l3extRsNodeL3OutAtt',
            aci_rn='rsnodeL3OutAtt-[{0}]'.format(fabric_node),
            module_object=fabric_node,
            target_filter={'name': fabric_node},
        ),
        **subclass_4=dict(**
            **aci_class='ipRouteP',**
            **aci_rn='rt-[{0}]'.format(prefix),**
            **module_object=prefix,**
            **target_filter={'name': prefix},**
        **),**
        **child_classes=child_classes**
    )

12. aci.get_existing() should remain as is. It is used to get the existing configuration of 'ipRouteP'.

13. When state is present, we need to construct a payload which will be posted to APIC. Payload takes class_config and child_config. The class_config has the main attributes. If new attributes are added in new versions of APIC, we will add that attribute to class_config only if it is assigned a value.

.. code-block:: python

      if state == 'present':
        child_configs = []
        class_config = dict(
            descr=description,
            ip=prefix,
            pref=preference,
            nameAlias=name_alias,
        )
        if bfd is not None:
            class_config['rtCtrl'] = bfd

        if track_policy is not None:
            tDn = 'uni/tn-{0}/tracklist-{1}'.format(tenant, track_policy)
            child_configs.append({'ipRsRouteTrack': {'attributes': {'tDn': tDn}}})

        aci.payload(
            aci_class='ipRouteP',
            class_config=class_config,
            child_configs=child_configs
        ),


14. The payload function is followed by get_diff(), which is used to get the difference between the proposed and existing configurations of 'ipRouteP'. Here, the aci_class is changed to the class name your module is going to manage.

.. code-block:: python

       #aci.get_diff(aci_class='l3extRsNodeL3OutAtt')
       aci.get_diff(aci_class='ipRouteP')

       aci.post_config()

15. The end of the module does not change and generally remains as is.

.. code-block:: python

      elif state == 'absent':
          aci.delete_config()

      aci.exit_json()


    if __name__ == '__main__':
        main()

Testing Our Module
------------------

Now that we have seen how a module can be built using another, let us look at testing our module. We need to test our module to make sure that it works for all states: present, absent, and query. The following section shows a basic and practical approach to building a test file with the help of another test file. This makes it easier to complete the test file without having to write everything from scratch.

Let's build a test file for our l3out static routes using the existing test for l3out logical node:
aci_l3out_logical_node -> aci_l3out_static_routes

1. In the **tests** directory of our collection, we have the **integration** directory. The **integration** directory consists of **targets**, which has directories for all the test files of modules that currently exist in our collection. We go to the **targets** directory and copy the aci_l3out_logical_node directory, then paste it in the same directory as aci_l3out_static_routes, which should be the same as the name of our module. Upon opening the directory, we find the main.yml file. We open this file and make the following changes.

2. The copyright section should be changed to your credentials.

.. code-block:: yaml

   # Copyright: (c) <year>, <Name> (@<github id>)

2. The following section verifies that we have the ACI APIC host, ACI username, and ACI password defined in the inventory. These will be used in every task of the test file. The inventory file is located in the inventory directory. More information on this directory is given below, after the test file.

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
            output_level: debug

4. The next section deletes the tenant. This ensures that we don't have the root object configuration on our APIC. This is done to avoid idempotency issues later during the creation of other objects pertaining to our module. We verify the result of each task in the test file, which also checks for idempotency. If an object such as the tenant already exists before the test begins, these verification tests may fail.

.. code-block:: yaml

   - name: Remove the ansible_tenant
     aci_tenant:
       <<: *aci_info 
       tenant: ansible_tenant
       state: absent

5. We begin by adding tasks to post configuration to the APIC. This includes creation of all the classes such as tenant and l3out that were used in the construct_url function in our module.

.. code-block:: yaml

      - name: Add a new tenant
        aci_tenant:
          <<: *aci_info 
          tenant: ansible_tenant
          description: Ansible tenant
          state: present

      - name: Add a new L3Out
        aci_l3out:
          <<: *aci_info
          tenant: ansible_tenant
          name: ansible_l3out
          description: L3Out for ansible_tenant tenant
          domain: ansible_dom
          vrf: ansible_vrf
          l3protocol: ospf
          route_control: export
          state: present

      - name: Add a logical node
        cisco.aci.aci_l3out_logical_node:
          <<: *aci_info
          tenant: ansible_tenant
          l3out: ansible_l3out
          logical_node: lNode
          pod_id: 1
          node_id: 101
          router_id: "10.1.0.1"
          router_id_as_loopback: 'yes'
          state: present

.. code-block:: text

6. The next section consists of adding tasks for all aspects of our module. We include Ansible's register attribute to save the result of the task. The procedure is as follows:
   1. We include the task for adding aci_l3out_static_routes using state: present with no attribute bfd. It consists of most attributes defined in our module.
   2. We include the task for adding aci_l3out_static_routes again using state: present with the same attributes used in step 1 to check for idempotency.
   3. We include the task for adding aci_l3out_static_routes using state: present with the bfd attribute.
   4. We include the task for querying aci_l3out_static_routes for the new attribute bfd using state: query.
   5. We include the task for adding a new aci_l3out_static_routes using state: present.
   6. We include the task to query all aci_l3out_static_routes under the root object: tenant, using state: query.
   7. We include the task for deleting aci_l3out_static_routes using state: absent.

.. code-block:: yaml

      - name: Add static routes
        aci_l3out_static_routes:
          <<: *aci_info
          tenant: ansible_tenant
          l3out: ansible_l3out
          logical_node: lNode
          node_id: 101
          pod_id: 1 
          prefix: 10.1.0.1/24
          state: present
         register: static1

       - name: Add static routes again
         aci_l3out_static_routes:
          <<: *aci_info
          tenant: ansible_tenant
          l3out: ansible_l3out
          logical_node: lNode
          node_id: 101
          pod_id: 1 
          prefix: 10.1.0.1/24
          state: present
         register: static2
        
      - name: Add static routes containing bfd
         aci_l3out_static_routes:
          <<: *aci_info
          tenant: ansible_tenant
          l3out: ansible_l3out
          logical_node: lNode
          bfd: bfd
          node_id: 101
          pod_id: 1 
          prefix: 10.1.0.1/24
          state: present
         register: static_bfd
         
       - name: Query static routes containing bfd
         aci_l3out_static_routes:
          <<: *aci_info
          tenant: ansible_tenant
          l3out: ansible_l3out
          logical_node: lNode
          node_id: 101
          pod_id: 1
          bfd: bfd
          prefix: 10.1.0.1/24
          state: query
        register: query_static_bfd
        
      - name: Add another static route
         aci_l3out_static_routes:
          <<: *aci_info
          tenant: ansible_tenant
          l3out: ansible_l3out
          logical_node: lNode
          node_id: 101
          pod_id: 1 
          prefix: 10.1.0.0/24
          state: present
         register: static_another

      - name: Query all static routes
        aci_l3out_static_routes:
          <<: *aci_info
          tenant: ansible_tenant
          state: query
        register: static_all

      - name: Remove static routes
        aci_l3out_static_routes:
          <<: *aci_info
          tenant: ansible_tenant
          l3out: ansible_l3out
          logical_node: lNode
          node_id: 101
          pod_id: 1
          prefix: 10.1.0.1/24
          state: absent
         register: delete_static
         

.. code-block:: text

After inclusion of all the tasks, the configuration has been posted, modified, and deleted on our APIC. By using the values registered with results after each task, we can verify these results by comparing them with the expected response from the APIC. The result stored in the registered value is a list of dictionaries, and we access the attributes using the dot operator. If all the verifications below pass, our testing is complete.

.. code-block:: yaml

      - name: Verify nm_add_node
        assert:
          that:
            - static1 is changed
            - static2 is not changed
            - static_bfd is changed
            - static1.current.0.ipRouteP.attributes.dn == "uni/tn-ansible_tenant/out-ansible_l3out/lnodep-lNode/rsnodeL3OutAtt-[topology/pod-1/node-101]/rt-[10.1.0.1/24]"
            - static2.current.0.ipRouteP.attributes.dn == "uni/tn-ansible_tenant/out-ansible_l3out/lnodep-lNode/rsnodeL3OutAtt-[topology/pod-1/node-101]/rt-[10.1.0.1/24]"
            - static_bfd.current.0.ipRouteP.attributes.dn == "uni/tn-ansible_tenant/out-ansible_l3out/lnodep-lNode/rsnodeL3OutAtt-[topology/pod-1/node-101]/rt-[10.1.0.1/24]"
            - static_bfd.current.0.ipRouteP.attributes.rtCtrl == "bfd"
            - query_static_bfd.current.0.ipRouteP.attributes.dn == "uni/tn-ansible_tenant/out-ansible_l3out/lnodep-lNode/rsnodeL3OutAtt-[topology/pod-1/node-101]/rt-[10.1.0.1/24]"
            - query_static_bfd.current.0.ipRouteP.attributes.rtCtrl == "bfd"
            - static_all.current | length == 2
            - delete_static.current == []

Sanity Checks, Testing ACI Integration, and Generating Coverage Report
---------------------------------------------------------------------
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

.. code-block:: text

   ansible-galaxy collection build --force builds a collection artifact that can be stored in a central repository. By default, this command builds from the current working directory, which in our case is ansible-aci.

   ansible-galaxy collection install cisco-aci-* --force installs the built collection in our current working directory, ansible-aci.

   cd ~/.ansible/collections/ansible_collections/cisco/aci changes our directory to aci, where tests are performed.

   ansible-test sanity --docker --color --truncate 0 -v is used to run sanity tests inside Docker, which already has all the dependencies.

   ansible-test network-integration --docker --color --truncate 0 -vvv --coverage aci_<your module name> is used to run integration tests inside Docker. We can either run the integration test on one module or all the modules by omitting the name altogether.

   We add the --coverage option to any test command to collect code coverage data:
   1. ansible-test coverage report
   2. ansible-test coverage html
   3. open ~/.ansible/collections/ansible_collections/cisco/aci/tests/output/reports/coverage/index.html

.. seealso::

   `ACI Fundamentals: ACI Policy Model <https://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/1-x/aci-fundamentals/b_ACI-Fundamentals/b_ACI-Fundamentals_chapter_010001.html>`_
       A good introduction to the ACI object model.
   `APIC Management Information Model reference <https://developer.cisco.com/docs/apic-mim-ref/>`_
       Complete reference of the APIC object model.
   `APIC REST API Configuration Guide <https://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/2-x/rest_cfg/2_1_x/b_Cisco_APIC_REST_API_Configuration_Guide.html>`_
       Detailed guide on how the APIC REST API is designed and used, including many examples.
