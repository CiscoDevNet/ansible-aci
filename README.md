# ansible-aci

The ansible-aci project provides an Ansible collection for managing and automating your Cisco ACI environment. It consists of a set of modules and roles for performing tasks related to ACI.

This collection has been tested and supports ACI 3.2+.
Modules supporting new features introduced in ACI API in specific ACI versions might not be supported in earlier ACI releases.

*Note: This collection is not compatible with versions of Ansible before v2.8.*

## Requirements
Ansible v2.9 or newer

## Install
Ansible must be installed
```
sudo pip install ansible
```

Install the collection
```
ansible-galaxy collection install cisco.aci
```
## Use
Once the collection is installed, you can use it in a playbook by specifying the full namespace path to the module, plugin and/or role.

```
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
### See Also:

* [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

Ongoing development efforts and contributions to this collection are tracked as issues in this repository.

We welcome community contributions to this collection. If you find problems, need an enhancement or need a new module, please open an issue or create a PR against the [Cisco ACI collection repository](https://github.com/CiscoDevNet/ansible-aci/issues).