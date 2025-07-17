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
      │  │  ├─ constants.py
      │  ├─ doc_fragments/
      │  │  ├─ aci.py
      |  │  ├─ annotation.py
      │  │  ├─ owner.py
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

   The **doc_fragments** directory has the aci.py file, which serves as a plugin and is used in each module's documentation. Every module has its own documentation section, but all the modules also share some common documentation elements, such as authentication details, notes: or seealso: entries. To avoid duplication of that information in each module's documentation block, it can be saved once in doc_fragments and used by all modules.

**tests** 
  This is where the different tests are defined. We run all sanity, unit, and integration tests on every code submission to the repository.

   The **integration** directory in **tests** consists of the **targets** directory, which has test directories for most of the modules present in our collection. Each module has its own test directory, and each directory is similar to an ansible role and contains a tasks directory, which contains a main.yml file. The main.yml file consists of tasks covering every functionality that a module provides. If the main.yml becomes too big, it can be split into multiple .yml files, and each of those can be imported into the main.yml file. Integration tests are run on every code submission to the repository. Every new module submission, bug fix or enhancement requires a test file or a change to an existing test file. This ensures that the code in our module is usable and robust.

   The **integration** directory also consists of the **inventory.networking** file, which defines the hosts, groups of hosts, and variables used by the integration tests role defined in the integration's targets directory.

**changelogs**
  This directory consists of a record of all the changes made to the project.

   The **changelog.yml** file contains a chronologically ordered list of collection versions and the changes included in those versions. This file is used to generate the changelog.rst file. The changes are categorized into major changes, minor changes and bugfixes.

   The **config.yml** file contains configuration options used by the ansible-changelog tool to generate the **changelog.rst** file.

**galaxy.yml** 
   The **galaxy.yml** file is placed in the root directory of the collection. This file contains the metadata of the collection that is used to generate an ansible-aci collection object. It is also used for information in Ansible Galaxy.

.. _cisco_aci_collection_structure: