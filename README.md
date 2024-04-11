# ansible-aci

The ansible-aci project provides an Ansible collection for managing and automating your Cisco ACI environment. It consists of a set of modules and roles for performing tasks related to ACI.

This collection has been tested and supports ACI 3.2+.
Modules supporting new features introduced in ACI API in specific ACI versions might not be supported in earlier ACI releases.

*Note: This collection is not compatible with versions of Ansible before v2.8.*

## Requirements

Ansible v2.14 or newer

## Install

Ansible must be installed

```sh
sudo pip install ansible
```

Install the collection

```sh
ansible-galaxy collection install cisco.aci
```

## Use

Once the collection is installed, you can use it in a playbook by specifying the full namespace path to the module, plugin and/or role.

```yml
- hosts: aci
  gather_facts: no

  tasks:
  - name: Add a new EPG
    cisco.aci.aci_epg:
      hostname: apic
      username: admin
      password: SomeSecretPassword
      tenant: production
      ap: intranet
      epg: web_epg
      description: Web Intranet EPG
      bd: prod_bd
    delegate_to: localhost
```

## Optimizing Playbooks

To find out more about optimizing playbook execution, please refer to the [Optimizing Playbooks](docs/optimizing.md) documentation.

## Update

Getting the latest/nightly collection build

### First Approach

Clone the ansible-aci repository.

```sh
git clone https://github.com/CiscoDevNet/ansible-aci.git
```

Go to the ansible-aci directory

```sh
cd ansible-aci
```

Pull the latest master on your aci

```sh
git pull origin master
```

Build and Install a collection from source

```sh
ansible-galaxy collection build --force
ansible-galaxy collection install cisco-aci-* --force
```

### Second Approach

Go to [ansible-aci Actions](https://github.com/CiscoDevNet/ansible-aci/actions)

Select the latest CI build

Under Artifacts download collection and unzip it using Terminal or Console.

*Note: The collection file is a zip file containing a tar.gz file. We recommend using CLI because some GUI-based unarchiver might unarchive both nested archives in one go.*

Install the unarchived tar.gz file

```sh
ansible-galaxy collection install cisco-aci-1.0.0.tar.gz —-force
```

### See Also

- [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

Ongoing development efforts and contributions to this collection are tracked as issues in this repository.

We welcome community contributions to this collection. If you find problems, need an enhancement or need a new module, please open an issue or create a PR against the [Cisco ACI collection repository](https://github.com/CiscoDevNet/ansible-aci/issues).
