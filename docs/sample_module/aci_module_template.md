```python

  #!/usr/bin/python
  # -*- coding: utf-8 -*-

  # Copyright: (c) <year>, <author_name> (@author_github_handle)
  # GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

  from __future__ import absolute_import, division, print_function

  __metaclass__ = type

  ANSIBLE_METADATA = {
      "metadata_version": "1.1",
      "status": ["preview"],
      "supported_by": "community",
  }

  DOCUMENTATION = r"""
  ---
  module: aci_<name_of_module> # Replace <module_name> with aci_l3out_interface
  short_description: Short description of the module being created (config:<name_of_class>). # Replace (config:<name_of_class>) with config value and name of the class based on the module requirements Ex: (l3ext:RsPathL3OutAtt)
  description:
  - Manages <functionality> on Cisco ACI fabrics.
  - This module is only available for APIC version x.y and above.
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
  - cisco.aci.annotation
  - cisco.aci.owner

  notes:
  - The C(root_object), C(parent_object), C(object_prop), used must exist before using this module in your playbook.
  The M(cisco.aci.aci_root_object_module) and M(cisco.aci.parent_object_module) modules can be used for this.
  #  Change the above lines with respect to the object in the module.
  #  For example for (l3ext:RsPathL3OutAtt) object
  #  - The C(tenant), C(l3out), C(logical_node), C(prefix), C(node_id) and C(pod_id) used must exist before using this module in your playbook.
  #    The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_l3out) modules can be used for this.

  seealso:
  - module: cisco.aci.aci_root_object_module
  - module: cisco.aci.aci_parent_object_module
  #  change the module values with required module names for the object
  #  For example for (l3ext:RsPathL3OutAtt) object 
  #  - module: cisco.aci.aci_tenant
  #  - module: cisco.aci.aci_l3out
  - name: APIC Management Information Model reference
    description: More information about the internal APIC class B(config:<name_of_class>). # for example change B(config:<name_of_class>) to B(l3ext:RsPathL3OutAtt)
    link: https://developer.cisco.com/docs/apic-mim-ref/
  author:
  - <author's name> (<author's github id>) # replace the author's name and github id

  """

  EXAMPLES = r"""
    - name: Add a new object # Always follow the same order -> Add, Query, Query all, Remove
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

  RETURN = r"""
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
    """

  from ansible.module_utils.basic import AnsibleModule
  from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec # use aci_annotation_spec, aci_owner_spec only if supported by the module


  def main():
      argument_spec = aci_argument_spec()
      argument_spec.update(aci_annotation_spec()) # use only if the module supports annotations
      argument_spec.update(aci_owner_spec()) # use only if the module supports owner
      argument_spec.update( # This section should contain all the parameters defined in the module's documentation
          object_id=dict(type='str', aliases=['name']),
          object_prop1=dict(type='str'),
          object_prop2=dict(type='str', choices=['choice1', 'choice2', 'choice3']),
          object_prop3=dict(type='int'),
          parent_id=dict(type='str'),
          child_object_id=dict(type='str'),
          child_object_prop=dict(type='str'),
          state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
      )

      module = AnsibleModule(
          argument_spec=argument_spec,
          supports_check_mode=True,
          required_if=[
              ['state', 'absent', ['object_id', 'parent_id']],
              ['state', 'present', ['object_id', 'parent_id']],
          ],
      )

      object_id = module.params.get('object_id')
      object_prop1 = module.params.get('object_prop1')
      object_prop2 = module.params.get('object_prop2')
      object_prop3 = module.params.get('object_prop3')
      if object_prop3 is not None and object_prop3 not in range(x, y):
          module.fail_json(msg='Valid object_prop3 values are between x and (y-1)')
      child_object_id = module.params.get('child_object_id')
      child_object_prop = module.params.get('child_object_prop')
      state = module.params.get("state")

      aci = ACIModule(module)

      aci.construct_url(
          root_class=dict(
            aci_class='fvTenant',
            aci_rn='tn-{0}'.format(tenant),
            module_object=tenant,
            target_filter={'name': tenant}
        ),
          subclass_1=dict(
            aci_class='<object_class>',
            aci_rn='<object_key>-{0}'.format(object_id),
            module_object=object_id,
            target_filter={'name': object_id}
          )
      )
      # If "dn" = "uni/tn-ansible_tenant/out-ansible_l3out/lnodep-ansible_node_profile/", the subclass_1 will look like below:
      # subclass_1=dict(
      #   aci_class='l3extOut',
      #   aci_rn='out-{0}'.format(l3out),
      #   module_object=l3out,
      #   target_filter={'name': l3out}
      # )
      #
      #  followed by subclass_2 for lnodep- and child_classes if required.
      aci.get_existing()

      if state == "present":
          aci.payload(
              aci_class='<object APIC class>', # Replace <object APIC class> with the actual APIC class name, e.g., 'l3extOut'
              class_config=dict(
                  name=object_id,
                  prop1=object_prop1,
                  prop2=object_prop2,
                  prop3=object_prop3,
              ),
              child_configs=[
                  dict(
                      '<child APIC class>'=dict( # Replace <child APIC class> with the actual child APIC class name, e.g., 'hsrpRsIfPol'
                          attributes=dict(
                              child_key=child_object_id,
                              child_prop=child_object_prop
                          ),
                      ),
                  ),
              ],
          )

          aci.get_diff(aci_class='<object APIC class>') # Replace <object APIC class> with the actual APIC class name, e.g., 'l3extOut'

          aci.post_config()

      elif state == "absent":
          aci.delete_config()

      aci.exit_json()


  if __name__ == "__main__":
      main()
  
```