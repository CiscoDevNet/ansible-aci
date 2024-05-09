# Optimizing Playbooks

The combined use of the following optimizations can reduce playbook execution time when compared to default behavior. This reduction can be significant in some circumstances.

## Using the ACI HTTPAPI plugin

The Ansible ACI HTTPAPI plugin instructs Ansible how to interact with an APIC's HTTP based API and execute tasks on the APIC.

### Benefits

- The ACI login credentials and ansible variables can stay in the inventory.
- Logs in once and executes subsequent tasks without requiring additional logins when using password-based authentication.
- Automatically refreshes password-based logins if the token expires during the playbook.
- Assists with overcoming rate limiting on logins.
- Leverages APIC's high availability by allowing a list of APIC hosts to be defined as a single ansible host.

### Enabling the plugin

The httpapi plugin can be enabled by setting the following variables:

```ini
ansible_connection=ansible.netcommon.httpapi
ansible_network_os=cisco.aci.aci
```

Instead of using `hostname`, `username` & `password` in the playbook, the following variables can be used in the inventory.

```ini
ansible_user=apicUser
ansible_password="SomeSecretPassword"
```

The `ansible_host` variable can contain one or more APIC hosts separated by a comma. If multiple hosts are defined the plugin will try executing tasks on the hosts in the order listed until one completes or they all fail.

```ini
single_apic  ansible_host=apic.host
cluster_apic ansible_host=apic1.host,apic2.host,apic3.host
```

Signature-based authentication can be specified in the inventory.

```ini
ansible_httpapi_session_key={'admin': "{{ lookup('file', 'admin.key')}}"}
```

> [!NOTE]
> `ansible_httpapi_session_key` takes precedence over `ansible_password`.

> [!TIP]
> Using signature-based authentication with or without ACI HTTPAPI enabled has the same execution time benefit.

### Full Example Inventory using ACI HTTPAPI plugin

```ini
[aci]
single_apic  ansible_host=apic.host
cluster_apic ansible_host=apic1.host,apic2.host,apic3.host

[aci:vars]
ansible_user=admin
ansible_password="SomeSecretPassword"
ansible_connection=ansible.netcommon.httpapi
ansible_network_os=cisco.aci.aci
```

## Using the `suppress_` options

Users of all ACI modules have two options for optimizing playbook performance by decreasing API calls. These parameters can improve playbook performance while disabling some module functionality. The goal of these suppress options is to limit the number of GET API calls to APIC, hence reducing APIC's workload and increasing playbook execution speed.

### `suppress_previous`

If enabled, a GET call to check previous object state will not be sent before a POST update to APIC.

> [!WARNING]
> This causes the previous return value to be empty. The previous state of the object will not be checked and POST update calls to APIC will contain all properties specified in the task.

#### `suppress_previous` Aliases

- `no_previous`
- `ignore_previous`

#### `suppress_previous` Example

```yml
- hosts: aci
  gather_facts: no

  tasks:
  - name: Add a new EPG
    cisco.aci.aci_epg:
      tenant: production
      ap: intranet
      epg: web_epg
      description: Web Intranet EPG
      bd: prod_bd
      suppress_previous: true
```

### `suppress_verification`

If enabled, a verifying GET call to check current object state will not be sent after a POST call to APIC.

> [!WARNING]
> This causes the current return value to be set to the proposed value. The current object state including default values will be unverifiable until another task executes for the same object.

#### `suppress_verification` Aliases

- `no_verification`
- `no_verify`
- `suppress_verify`
- `ignore_verify`
- `ignore_verification`

#### `suppress_verification` Example

```yml
- hosts: aci
  gather_facts: no

  tasks:
  - name: Add a new EPG
    cisco.aci.aci_epg:
      tenant: production
      ap: intranet
      epg: web_epg
      description: Web Intranet EPG
      bd: prod_bd
      suppress_verification: true
```
