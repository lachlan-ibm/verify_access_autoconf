#!/bin/python3
"""
@copyright: IBM
"""

import logging
import json
import os
import typing
import copy

from .util.configure_util import config_base_dir, deploy_pending_changes
from .util.data_util import Map, FILE_LOADER, optional_list, filter_list

_logger = logging.getLogger(__name__)

class AAC_Configurator(object):

    config = Map()
    aac = None
    factory = None
    needsRestart = True

    def __init__(self, config, factory):
        self.aac = factory.get_access_control()
        self.factory = factory
        self.config = config


    class Push_Notification_Provider(typing.TypedDict):
        '''
        Example::

                push_notification_providers:
                - platform: "android"
                  app_id: "com.ibm.security.verifyapp"
                  provider: "imc"
                  provider_address: "verifypushcreds.mybluemix.net"
                  imc_app_key: !secret default/isva-secrets:android_app_key
                  imc_client_id: !secret default/isva-secrets:android_client_id
                  imc_client_secret: !secret default/isva-secrets:android_client_secret
                  imc_refresh_token: !secret default/isva-secrets:android_refresh_token
                - platform: "apple"
                  app_id: "com.ibm.security.verifyapp"
                  provider: "imc"
                  provider_address: "verifypushcreds.mybluemix.net"
                  imc_app_key: !secret default/isva-secrets:apple_app_key
                  imc_client_id: !secret default/isva-secrets:apple_client_id
                  imc_client_secret: !secret default/isva-secrets:apple_client_secret
                  imc_refresh_token: !secret default/isva-secrets:apple_refresh_token

        '''

        app_id: str
        'The application identifier associated with the registration.'
        platform: str
        'The platform the registration is for. Valid values are "apple", or "android".'
        provider_address: str
        'The "host:port" address of the push notification service provider.'
        apple_key_store: typing.Optional[str]
        'The key store database containing the APNS certificate. Only valid if ``platform`` is "apple".'
        apple_key_label: typing.Optional[str]
        'The key label of the imported APNS certificate. Only valid if ``platform`` is "apple".'
        firebase_server_key: typing.Optional[str]
        'The server key for access to the Firebase push notification service. Only valid if ``platform`` is "android".'
        imc_client_id: typing.Optional[str]
        'The IBM Marketing Cloud issued Oauth client ID.'
        imc_client_secret: typing.Optional[str]
        'The IBM Marketing Cloud issued Oauth client secret.'
        imc_refresh_token: typing.Optional[str]
        'The IBM Marketing Cloud issued Oauth refresh token.'
        imc_app_key: typing.Optional[str]
        'The app key issued by IBM Marketing Cloud for the associated application.'

    def push_notifications(self, config):
        if config.push_notification_providers:
            existing_pnp = optional_list(self.aac.push_notification.list_providers().json)
            for provider in config.push_notification_providers:
                rsp = None; verb = 'None'
                old_pnp = optional_list(filter_list('app_id', provider.app_id, existing_pnp))[0]
                if old_pnp:
                    rsp = self.aac.push_notification.update_provider(old_pnp['pnr_id'], **provider)
                    verb = 'modified' if rsp.success == True else 'modify'
                else:
                    rsp = self.aac.push_notification.create_provider(**provider)
                    verb = 'created' if rsp.success == True else 'create'
                if rsp.success == True:
                    _logger.info("Successfully {} {} push notification provider".format(verb, provider.app_id))
                else:
                    _logger.error("Failed to {} push notification provider:\n{}\n{}".format(verb, 
                                                                json.dumps(provider, indent=4), rsp.data))


    class Risk_Profiles(typing.TypedDict):
        '''
        Example::

                risk_profiles:
                - name: "myLocation"
                  active: true
                  attributes:
                  - weight: 50
                    id: "28"
                  - weight: 10
                    name: "geoCountryCode"
                  - weight: 10
                    name: "geoRegionCode"
                  - weight: 10
                    name: "geoCity"
                  predefined: false

        '''
        class Attribute(typing.TypedDict):
            weight: int
            'Determines the importance of this attribute within the associated risk profile. A higher weight value indicates the attribute has more importance within the risk profile. The weight values of the attributes are used in determining the risk score or the level of risk associated with permitting a request to access a resource.'
            id: typing.Optional[str]
            'Internally assigned ID value of the attribute. The attribute must have a type field value of ``true`` for "risk". Either the name or id of the attribute must be defined.'
            name: typing.Optional[str]
            'Name of the attribute. The attribute must have a type field value of ``true`` for "risk". Either the name or id of the attribute must be defined.'

        name: str
        'A unique name for the risk profile.'
        description: typing.Optional[str]
        'An optional brief description of the risk profile.'
        active: bool
        'True indicates this risk profile is the currently active risk profile. Only one profile can be active at a time.'
        attributes: typing.Optional[typing.List[Attribute]]
        'Array of attributes comprising this risk profile and the weight value of each attribute which is used in determining the risk score.'
        predefined: typing.Optional[bool]
        'False to indicate this risk profile is custom defined.'

    def _remap_attribute_name_to_id(self, all_attributes, risk_profile):
        for attribute in risk_profile['attributes']:
            for attribute_def in all_attributes:
                if "name" in attribute and attribute['name'] == attribute_def['name']:
                    attribute.pop('name')
                    attribute["attributeID"] = attribute_def["id"]
                elif "id" in attr:
                    attribute["attributeID"] = attribute.pop("id")

    def risk_profiles(self, config):
        if config.risk_profiles:
            attributes = optional_list(self.aac.attributes.list_attributes().json)
            old_profiles = optional_list(self.aac.risk_profiles.list().json)
            for profile in config.risk_profiles:
                methodArgs = copy.deepcopy(profile)
                #Re-map attribute name and id keys to correct property
                if "attributes" in methodArgs.keys():
                    self._remap_attribute_name_to_id(attributes, methodArgs)
                rsp = None
                verb = None
                old_profile = optional_list(filter_list('name', profile.name, old_profiles))[0]
                if old_profile:
                    rsp = self.aac.risk_profiles.update(old_profile['id'], **methodArgs)
                    verb = "updated" if rsp.success == True else "update"
                else:
                    rsp = self.aac.risk_profiles.create(**methodArgs)
                    verb = "created" if rsp.success == True else "create"
                if rsp.success == True:
                    _logger.info("Successfully {} {} risk profile".format(verb, profile.name))
                else:
                    _logger.error("Failed to {} risk profile:\n{}\n{}".format(
                                            verb, json.dumps(profile, indent=4), rsp.data))


    class Policy_Information_Points(typing.TypedDict):
        '''
        Example::

                pips:
                - name: "myJSpip"
                  description: "Custom JavaScript PIP."
                  type: "JavaScript"                  
                  properties:
                  - read_only: false
                    value: |
                        /** Import packages necessary for the script to execute. */
                        importPackage(com.ibm. . .);
                        /** Your code here */
                        ....
                        var name = getName();
                        return
                    datatype: "JavaScript"
                    key: "javascript.code"
                    sensitive: false
                  - read_only: false
                    value: "89"
                    datatype: "Integer"
                    key: "limit"
                    sensitive: false

        '''
        class Policy_Information_Point(typing.TypedDict):

            class Property(typing.TypedDict):
                read_only: bool
                'True if the property value cannot be updated.'
                value: str
                'Value given to the property.'
                datatype: str
                'Data type of the property. Valid values include "Binary", "Boolean", "Double", "Integer", "String", "JavaScript", "KeyStore", "Email", "X500", "URI", "URL", and "Hostname".'
                key: str
                'Name of the property as used by the policy information point. A key of "javascript.code" or "fileContent" identify special properties whose values can be imported and exported by a file.'
                sensitive: bool
                'Used internally to indicate properties with values private in nature, such as passwords.'

            class Attribute_Selector(typing.TypedDict):
                name: str
                'Name of the attribute whose value will come from the selected data portion of the policy information point response. The attribute must be defined on the appliance before it can be assigned to this selector.'
                selector: str
                'Identifies how to select the part of the policy information point response that will be assigned as the attribute value. The format of the selector for a RESTful Web Service policy information point is dependent on the "responseFormat" property value, "JSON", "XML", or "Text".'

            name: str
            'A unique name for the policy information point. This name is used as the Issuer for custom attributes whose value is returned by this policy information point.'
            description: typing.Optional[str]
            'A description of the policy information point.'
            type: str
            'The policy information point type for this policy information point. Valid types are: "JavaScript", "RESTful Web Service", "Database", "LDAP", "FiberLink MaaS360", and "QRadar User Behavior Analytics".'
            attributes: typing.List[Attribute_Selector]
            'A list of custom attributes whose values are retrieved from select portions of the response from this policy information point. Specify when the policy information point type of this policy information point has supportSelector true.'
            properties: typing.List[Property]
            'Configurable properties defining this policy information point. These entries are specific to the policy information point type.'

        pips: typing.List[Policy_Information_Point]
        'List of policy information points to configure.'

    def pip_configuration(self, config):
        if config.pips:
            existing = self.aac.pip.list_pips().json
            if not existing: existing = []
            for pip in config.pips:
                methodArgs = copy.deepcopy(pip)
                if "properties" in methodArgs.keys():
                    for k, v in methodArgs["properties"].items():
                        if k == "read_only":
                            methodArgs["properties"]["readOnly"] = methodArgs["properties"].pop("read_only")
                old = filter_list('name', pip.name, existing)
                rsp = None
                verb = None
                if old:
                    old = old[0]
                    rsp = self.aac.pip.update_pip(old['id'], **pip)
                    verb = "updated" if rsp.success == True else "update"
                else:
                    rsp = self.aac.pip.create_pip(**pip)
                    verb = "created" if rsp.success == True else "create"
                if rsp.success == True:
                    _logger.info("Successfully {} {} PIP".format(verb, pip.name))
                else:
                    _logger.error("Failed to {} PIP:\n{}\n{}".format(verb, json.dumps(pip, indent=4), rsp.data))
                    

    def _cba_resource(self, resource, policies, policy_sets, definitions):
        methodArgs = {
            "server": resource.server,
            "resource_uri": resource.uri,
            "policies": [],
            "policy_combining_algorithm": resource.policy_combining_algorithm,
            "cache": resource.cache
        }
        if resource.policies: #remap policy names to Verify Access uuids
            policyArg = []
            for policy in resource.policy:
                policy_id = "-1"
                if policy.type == "policy":
                    policy_id = optional_list(filter_list("name", policy.name, policies)).get('id', "-1")
                elif policy.type == "policyset":
                    policy_id = optional_list(filter_list('name', policy.name, policy_sets))[0].get('id', "-1")
                elif policy.type == "definition":
                    policy_id = optional_list(filter_list('name', policy.name, definitions))[0].get('id', '-1')
                policyArg += [{"id": policy_id, "type": policy.type}]
            methodArgs['policies'] = policyArg
        rsp = self.aac.access_control.configure_resource(**methodArgs)
        if rsp.success == True:
            _logger.info("Successfully configured {} resource for {}".format(resource.uri, resource.server))
        else:
            _logger.error("Failed to create resource with configuration:\n{}\n{}".format(
                json.dumps(resource, indent=4), rsp.data))

    def _cba_policy(self, old_policies, policy):
        policy_id = None
        for p in old_policies:
            if p['name'] == policy.name:
                policy_id = p['id']
                break
        methodArgs = {
                "name": policy.name,
                "description": policy.description,
                "dialect": policy.dialect if policy.dialect else "urn:oasis:names:tc:xacml:2.0:policy:schema:os",
                "policy": policy.policy,
                "attributes_required": policy.attributes_required
            }
        rsp = None
        verb = None
        if policy_id:
            rsp = self.aac.access_control.update_policy(policy_id, **methodArgs)
            verb = "updated" if rsp.success == True else "update"
        else:
            rsp = self.aac.access_control.create_policy(**methodArgs)
            verb = "created" if rsp.success == True else "create"
        if rsp.success == True:
            _logger.info("Successfully {} {} Access Control Policy".format(verb, policy.name))
        else:
            _logger.error("Failed to {} Access Control Policy with config:\n{}\n{}".format(verb,
                                                                    json.dumps(policy, indent=4), rsp.data))


    class Access_Control(typing.TypedDict):
        '''
        Example::

                access_control:
                  policies:
                  - name: "Verify Demo - MFA Login Policy"
                  policy: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!-- PolicyTag=urn:ibm:security:isam:8.0:xacml:2.0:config-policy --><!-- PolicyName='Verify Demo - MFA Login Policy' --><PolicySet xmlns=\"urn:oasis:names:tc:xacml:2.0:policy:schema:os\" xmlns:xacml-context=\"urn:oasis:names:tc:xacml:2.0:context:schema:os\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"urn:oasis:names:tc:xacml:2.0:policy:schema:os http://docs.oasis-open.org/xacml/access_control-xacml-2.0-policy-schema-os.xsd\" PolicySetId=\"urn:ibm:security:config-policy\" PolicyCombiningAlgId=\"urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:deny-overrides\"><Description>Example CBA Policy for the MFA Banking Demo password-less login</Description><Target/><Policy PolicyId=\"urn:ibm:security:rule-container:0\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable\"><Target/><Rule RuleId=\"urn:ibm:security:rule:0\" Effect=\"Permit\"></Rule><Obligations><Obligation ObligationId=\"urn:ibm:security:authentication:asf:verify_mmfa_request_fingerprint\" FulfillOn=\"Permit\"/></Obligations></Policy></PolicySet>"
                  - name: "Verify Demo - EULA"
                  policy: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!-- PolicyTag=urn:ibm:security:isam:8.0:xacml:2.0:config-policy --><!-- PolicyName='Verify Demo - EULA' --><PolicySet xmlns=\"urn:oasis:names:tc:xacml:2.0:policy:schema:os\" xmlns:xacml-context=\"urn:oasis:names:tc:xacml:2.0:context:schema:os\" xmlns:xsi=\"http:\/\/www.w3.org\/2001\/XMLSchema-instance\" xsi:schemaLocation=\"urn:oasis:names:tc:xacml:2.0:policy:schema:os http:\/\/docs.oasis-open.org\/xacml\/access_control-xacml-2.0-policy-schema-os.xsd\" PolicySetId=\"urn:ibm:security:config-policy\" PolicyCombiningAlgId=\"urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:first-applicable\"><Description>GDPR Compliance (Acceptance of ToS)<\/Description><Target\/><Policy PolicyId=\"urn:ibm:security:rule-container:0\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable\"><Target\/><Rule RuleId=\"urn:ibm:security:rule:0\" Effect=\"Permit\"><Condition><Apply FunctionId=\"urn:oasis:names:tc:xacml:1.0:function:and\"><Apply FunctionId=\"urn:oasis:names:tc:xacml:1.0:function:string-at-least-one-member-of\"><Apply FunctionId=\"urn:oasis:names:tc:xacml:1.0:function:string-bag\"><AttributeValue DataType=\"http:\/\/www.w3.org\/2001\/XMLSchema#string\">urn:ibm:security:authentication:asf:mechanism:eula<\/AttributeValue><\/Apply><SubjectAttributeDesignator AttributeId=\"urn:ibm:security:subject:authenticationMechanismTypes\" DataType=\"http:\/\/www.w3.org\/2001\/XMLSchema#string\" MustBePresent=\"false\"\/><\/Apply><\/Apply><\/Condition><\/Rule><\/Policy><Policy PolicyId=\"urn:ibm:security:rule-container:1\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable\"><Target\/><Rule RuleId=\"urn:ibm:security:rule:1\" Effect=\"Permit\"><\/Rule><Obligations><Obligation ObligationId=\"urn:ibm:security:authentication:asf:eula\" FulfillOn=\"Permit\"\/><\/Obligations><\/Policy><\/PolicySet>"
                  description: "GDPR Compliance (Acceptance of ToS)"
                  resources:
                  - server: "my.ibmsec.idp"
                    resource_uri: "/login"
                    policies:
                    - name: "Verify Demo - MFA Login Policy"
                      type: "policy"
                  - server: "my.ibmsec.idp"
                    resource_uri: "/protected/transfer"
                    policies:
                    - name: "Verify Demo - MFA Transaction Policy"
                      type: "policy"
                  - server: "my.ibmsec.idp"
                    resource_uri: "/isam/sps/SP-SAML-QC/saml20/login"
                    policies:
                    - name: "Verify Demo - MFA Office 365 Login"
                      type: "policy"

        '''
        class Policy(typing.TypedDict):
            name: str
            'The name of the policy.'
            description: typing.Optional[str]
            'An optional description of the policy.'
            dialect: typing.Optional[str]
            'The XACML specification used within the policy. Only valid value is XACML Version 2, "urn:oasis:names:tc:xacml:2.0:policy:schema:os".'
            policy: str
            'The configured policy in XACML 2.0.'
            attributes_required: typing.Optional[typing.List[str]]
            'True if the values for any attributes specified in the policy must be present in the incoming request. False if the attribute values may optionally be present.'

        class Resource(typing.TypedDict):
            class Policy_Attachment(typing.TypedDict):
                name: str
                'Name of the policy, policy set, or API protection definition.'
                type: str
                'The type of attachment. Values include "policy", "policyset", or "definition".'

            server: str
            'The web container that contains the protected object space for a server instance.'
            resource_uri: str
            'The resource URI of the resource in the protected object space.'
            policies: typing.List[Policy_Attachment]
            'Array of attachments (policy, policy sets, and API protection definitions) that define the access protection for this resource.'
            policy_combining_algorithm: typing.Optional[str]
            '"permitOverrides" to allow access to the resource if any of the attachments return permit; "denyOverrides" to deny access to the resource if any of the attachments return deny. Default is "denyOverrides".'
            cache: int
            '0 to disable the cache for this resource, -1 to cache the decision for the lifetime of the session or any number greater than 1 to set a specific timeout (in seconds) for the cached decision. If not specified a default of 0 will be used.'

        policies: typing.Optional[typing.List[Policy]]
        'List of Risk Based Access policies to create.'
        resources: typing.Optional[typing.List[Resource]]
        'List of resources to be created and corresponding policies which should be attached to each resource.'

    def access_control(self, aac_config):
        if aac_config.access_control != None:
            cba = aac_config.access_control
            if cba.policies != None:
                old_policies = self.aac.access_control.list_policies().json
                if old_policies == None: old_policies = []
                for policy in ac.policies:
                    self._cba_policy(old_policies, policy)
            if cba.resources != None:
                for resource in cba.resources:
                    self._cba_resource(resource)


    class Advanced_Configuration(typing.TypedDict):
        '''
        Example::

                 advanced_configuration:
                 - name: "attributeCollection.authenticationContextAttributes"
                   value: "resource,action,ac.uuid,header:userAgent,urn:ibm:demo:transferamount"
                 - name: "mmfa.transactionArchival.maxPendingPerUser"
                   value: "1"

        '''
        id: typing.Optional[int]
        'The Verify Access assigned property id. Either the property ID or name must be defined.'
        name: typing.Optional[str]
        'The name of the advanced configuration property. Either the property ID or name must be defined.'
        value: str
        'The updated value of the advanced configuration property.'

    def advanced_config(self, aac_config):
        if aac_config.advanced_configuration != None:
            old_config = optional_list(self.aac.advanced_config.list_properties().json)
            for advConf in aac_config.advanced_configuration:
                old = None; id=None; sensitive=None
                if advConf.name:
                    old = optional_list(filter_list('key', advConf.name, old_config))[0]
                else:
                    old = optional_list(filter_list('id', advConf.id, old_config))[0]
                if not old:
                    _logger.error("Could not find {} in list of advanced configuration parameters".format(advConf.name))
                    continue
                rsp = self.aac.advanced_config.update(old['id'], value=advConf.value, sensitive=old.get('sensitive', None))
                if rsp.success == True:
                    _logger.info("Successfully updated advanced configuration {}".format(old['key']))
                else:
                    _logger.error("Failed to update advanced configuration with:\n{}\n{}".format(
                        json.dumps(advConf, indent=4), rsp.data))



    class System_CrossDomain_Identity_Management(typing.TypedDict):
        '''
        Example::

                 scim:
                   admin_group: "SecurityGroup"
                   schemas:
                   - schema: "urn:ietf:params:scim:schemas:core:2.0:User"
                     properties:
                       ldap_connection: "Local LDAP connection"
                       search_suffix: "dc=ibm,dc=com"
                       user_suffix: "dc=ibm,dc=com"
                   attribute_modes:
                   - schema: "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction"
                     modes:
                     - attribute: "transactionsPending"
                       mode: "readwrite"
                     - attribute: "transactionsPending"
                       subattribute: "txnStatus"
                       mode: "readwrite"

        '''

        class AttributeMode(typing.TypedDict):

            class Mode(typing.TypedDict):
                attribute: str
                'The name of the attribute.'
                mode: str
                'The mode for the attribute: "readonly", "writeonly", "readwrite", "adminwrite" or "immutable".'
                subatttribute: str
                'For a multivalued attribute - the second level SCIM attribute name. '

            schema: str
            'The name of the schema.'
            modes: typing.List[Mode]
            'An array of customised attribute modes for the schema.'

        class Schema(typing.TypedDict):

            class UserSchemaProperties(typing.TypedDict):
                '''
                "urn:ietf:params:scim:schemas:core:2.0:User"
                '''
                class SCIMMapping(typing.TypedDict):
                    class Mapping(typing.TypedDict):
                        type: str
                        'The type of attribute to map to the SCIM attribute: "ldap" "session" or "fixed".'
                        source: str
                        'The attribute to map to the SCIM attribute.'
                        scim_subattribute: str
                        'For a multivalued attribute - the second level SCIM attribute name to be mapped. Eg: work or home for SCIM attribute email.'

                    scim_attribute: str
                    'The name of the SCIM attribute being mapped.'
                    mapping: Mapping
                    'For a simple SCIM attribute - the mapping for this attribute. For a complex SCIM attribute this can be an array of mappings.'

                class LDAPObjectClass(typing.TypedDict):
                    name: str
                    'The name of the ldap object class type that is used to indicate a user object.'

                ldap_connection: str
                'The name of the ldap server connection.'
                ldap_object_classes: typing.List[LDAPObjectClass]
                'The list of ldap object classes that are used to indicate a user object.'
                search_suffix: str
                'The suffix from which searches will commence in the LDAP server.'
                user_suffix: str
                'The suffix that will house any users that are created through the SCIM interface.'
                user_dn: typing.Optional[str]
                'The LDAP attribute that will be used to construct the user DN. Defaults to "cn".'
                connection_type: typing.Optional[str]
                'Indicates the type of ldap server connection type: "ldap" or "isamruntime". Defaults to "ldap"'
                attrs_dir: typing.Optional[str]
                'The name of a federated directory used to generate the list of available ldap object classes and ldap attribute names. Only valid if the connection_type is set to "isamruntime".'
                enforce_password_policy: bool
                'Set this field to true if SCIM needs to honour the backend password policy when changing a user password.'
                user_id: typing.Optional[str]
                'The LDAP attribute that will be used as the user ID. Defaults to "uid".'
                mappings: typing.Optional[typing.List[SCIMMapping]]
                'The list of SCIM attribute mappings.'

            class EnterpriseSchemaProperties(typing.TypedDict):
                '''
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
                '''
                class SCIMMapping(typing.TypedDict):
                    class Mapping(typing.TypedDict):
                        type: str
                        'The type of attribute to map to the SCIM attribute: "ldap" "session" or "fixed".'
                        source: str
                        'The attribute to map to the SCIM attribute.'
                        scim_subattribute: str
                        'For a multivalued attribute - the second level SCIM attribute name to be mapped. Eg: work or home for SCIM attribute email.'

                    scim_attribute: str
                    'The name of the SCIM attribute being mapped.'
                    mapping: Mapping
                    'For a simple SCIM attribute - the mapping for this attribute. For a complex SCIM attribute this can be an array of mappings.'

                mappings: typing.List[SCIMMapping]
                'The list of SCIM enterprise user attribute mappings.'

            class GroupSchemaProperties(typing.TypedDict):
                '''
                "urn:ietf:params:scim:schemas:core:2.0:Group"
                '''
                class LDAPObjectClass(typing.TypedDict):
                    name: str
                    'The name of the ldap object class type that is used to indicate a user object.'
                ldap_object_classes: typing.List[LDAPObjectClass]
                'The list of ldap object classes that are used to indicate a group object.'
                group_dn: str
                'The LDAP attribute that will be used to construct the group DN.'

            class ISVAUserSchemaProperties(typing.TypedDict):
                '''
                "urn:ietf:params:scim:schemas:extension:isam:1.0:User"
                '''
                ldap_connection: typing.Optional[str]
                'The name of the ldap server connection to the Verify Access user registry.  If a connection is not specified the SCIM application will not attempt to manage Verify Access users.'
                isam_domain: typing.Optional[str]
                'The name of the Verify Access domain. This will default to: "Default"'
                update_native_users: typing.Optional[bool]
                connection_type: typing.Optional[str]
                'Indicates the type of ldap server connection "ldap" or "isamruntime". Defaults to "ldap".'
                attrs_dir: typing.Optional[str]
                'The name of a federated directory used to generate the list of available ldap object classes and ldap attribute names. Only valid if the connection_type is set to "isamruntime". Default is not set.'
                enforce_password_policy: typing.Optional[bool]
                'Set this field to true if SCIM needs to honour the backend password policy when changing a user password. Defaults to false.'

            scheama: str
            'Name of schema properties to modify. See `.*SchemaProperties` classes for the valid schema names.'
            properties: typing.Union[ISVAUserSchemaProperties, GroupSchemaProperties, EnterpriseSchemaProperties, UserSchemaProperties]
            'Schema unique properties to apply.'

        admin_group: str
        'The name of the administrator group. Used to determine if the authenticated user is an administrator.'
        schema: typing.Optional[typing.List[Schema]]
        'List of managed schema to modify'
        enable_header_authentication: typing.Optional[bool]
        'Whether or not SCIM header authentication is enabled.'
        enable_authz_filter: typing.Optional[bool]
        'Whether or not the authorization filter is enabled.'
        attribute_modes: typing.Optional[typing.List[AttributeMode]]
        'The customized attribute modes.'
        max_user_response: typing.Optional[int]
        'The maximum number of entries that can be returned from a single call to the /User endpoint.'

    def scim_configuration(self, aac_config):
        if aac_config.scim != None:
            generalConfig = self.aac.scim_config.get_general_config().json
            needToUpdate = False
            for prop in ["admin_group", "enable_header_authentication", "enable_authz_filter", "max_user_response"]:
                if prop in aac_config.scim:
                    generalConfig[prop] = aac_config.scim.get(prop)
                    needToUpdate = True
            if aac_config.scim.attribute_modes:
                attrModes = generalConfig.pop("attribute_modes", {})
                attrModes.update(aac_config.scim.attribute_modes)
                generalConfig["attribute_modes"] = attrModes
                needToUpdate = True
            if needToUpdate == True:
                rsp = self.aac.scim_config.update_config(**generalConfig)
                if rsp.success == True:
                    _logger.info("Successfully updated the SCIM general configuration")
                else:
                    _logger.error("Failed to update SCIM general configuration:\n{}\n{}".format(
                                                        json.dumps(generalConfig, indent=4), rsp.data))
            for schema in aac_config.scim:
                rsp = self.aac.scim_config.get_schema(schema.uri)
                if rsp.success == False:
                    _logger.error("Failed to get config for schema [{}]".format(schema.uri))
                    return
                config = {**rsp.json, **schema.properties} # I wonder how this resolves conflicts
                rsp = self.aac.scim_config.update_schema(schema.uri, config)
                if rsp.success == True:
                    _logger.info("Successfully updated schema [{}]".format(schema.uri))
                else:
                    _logger.error("Failed to update schema [{}] with configuration:\n{}".format(
                        schema.uri, config))


    def _ci_server_connection(self, connection):
        props = connection.properties
        rsp = self.aac.server_connections.create_ci(name=connection.name, description=connection.description, locked=connection.locked,
                connection_host_name=props.hostname, connection_client_id=props.client_id, connection_client_secret=props.client_secret,
                connection_ssl_truststore=props.ssl_truststore)
        return rsp

    def _ldap_server_connection(self, connection):
        props = connection.properties
        rsp = self.aac.server_connections.create_ldap(name=connection.name, description=connection.description,
                locked=connection.locked, connection_host_name=prop.hostname, connection_bind_dn=props.bind_dn,
                connection_bind_pwd=props.bind_password, connection_ssl_truststore=props.key_file,
                connection_ssl_auth=props.key_label, connection_host_port=props.port, connection_ssl=props.ssl,
                connection_timeout=props.timeout, servers=props.servers)
        return rsp

    def _jdbc_server_connection(self, connection):
        props = connection.properties
        rsp = self.aac.server_connections.create_jdbc(name=connection.name, description=connection.description,
                locked=connection.locked, database_type=connection.type, connection_jndi=props.jndi, connection_hostname=props.hostname,
                connection_port=props.port, connection_ssl=props.ssl, connection_user=props.user, connection_password=props.password, 
                connection_type=props.type, connetion_service_name=props.service_name, conection_database_name=props.database_name, 
                connection_aged_timeout=props.aged_timeout, connection_connection_timeout=props.connection_timeout, 
                connection_per_thread=props.connections.per_thread, connection_max_idle=props.max_idle, connection_max_pool_size=props.max_pool_size, 
                connection_min_pool_size=props.min_pool_size, connection_connections_per_local_thread=props.connections_per_local_thread, 
                connection_purge_policy=props.purge_policy, connection_reap_time=props.reap_time)
        return rsp

    def _smtp_server_connection(self, connection):
        props = connection.properties
        rsp = self.aac.server_connections.create_smtp(name=connection.name, description=connection.description, connect_timeout=props.timeout,
                connection_host_name=props.hostname, connection_host_port=props.port, connection_ssl=props.ssl, connection_user=props.user,
                connection_password=props.password)
        return rsp

    def _ws_server_connection(self, connection):
        props = connection.properties
        rsp = self.aac.server_connection.screate_web_service(name=connection.name, description=connection.description,
                locked=connection.locked, connection_url=props.url, connection_user=props.user,
                connection_password=props.password, connection_ssl_truststore=props.key_file, 
                connection_ssl_auth_key=props.key_label, connection_ssl=props.ssl)
        return rsp

    def _remove_server_connection(self, connection):
        configured_connections = self.aac.server_connections.list_all().json
        print(configured_connections)
        for connectionType in configured_connections:
            print(connectionType)
            for c in configured_connections[connectionType]:
                print(c)
                if c.get('name') == connection.name and c.get('locked') == True:
                    _logger.error("Connection {} exists and is locked, skipping".format(connection.name))
                    return False
                elif c.get('name') == connection.name:
                    default_fcn = lambda x: _logger.error("Server connection id [{}] not found".format(x))
                    logger.info("connection {} exists, deleting before recreating".format(connection.name))
                    rsp = {"ci": self.aac.server_connections.delete_ci,
                          "ldap": self.aac.server_connections.delete_ldap,
                          "isamruntime": self.aac.server_connections.delete_runtime,
                          "oracle": self.aac.server_connections.delete_jdbc,
                          "db2": self.aac.server_connections.delete_jdbc,
                          "soliddb": self.aac.server_connections.delete_jdbc,
                          "postgresql": self.aac.server_connections.delete_jdbc,
                          "smtp": self.aac.server_connections.delete_smtp,
                          "ws": self.aac.server_connections.delete_web_service}.get(
                                                                    connection.type, default_fcn)(c['uuid'])
                    return False if rsp == None else rsp.success
        return True



    class Server_Connections(typing.TypedDict):
        '''
        Example::

                  server_connections:
                  - name: "intent-svc"
                    type: "web_service"
                    description: "A connection to the intent service."
                    properties:
                      url: "http://ibmsec.intent.svc:16080"
                      user: ""
                      password: ""
                      ssl: false
                  - name: "Cloud Identity tenant connection"
                    type: "ci"
                    description: "A connection to the companion CI Tenant."
                    properties:
                      ci_tenant: !secret default/isva-secrets:ci_tenant
                      ci_client_id: !secret default/isva-secrets:ci_client_id
                      ci_client_secret: !secret default/isva-secrets:ci_client_secret
                      ssl_truststore: "rt_profile_keys.kdb"
                  - name: "Local LDAP connection"
                    type: "ldap"
                    description: "A connection to this ISAMs LDAP."
                    locked: false
                    properties:
                      hostname: ibmsec.ldap.domain
                      port: 636
                      bind_dn: "cn=root,secAuthority=Default"
                      bind_password: !secret default/isva-secrets:ldap_bind_secret
                      ssl: true
                      ssl_truststore: "lmi_trust_store"
                    - name: "SCIM web service connection"
                      type: "web_service"
                      description: "A connection to this ISAMs SCIM server."
                      locked: false
                      properties:
                        url: https://ibmsec.runtime.svc
                        user: !secret default/isva-secrets:runtime_user
                        password: !secret default/isva-secrets:runtime_secret
                        ssl: true
                        key_file: "rt_profile_keys.kdb"

        '''
        class Server_Connection(typing.TypedDict):

            class IbmsecVerifyConnection(typing.TypedDict):
                '''
                ci
                '''
                admin_host: str
                'The IBM Security Verify administration host to connect to.'
                client_id: str
                'The client ID to authenticate to the IBM Security Verify tenant.'
                client_secret: str
                'The client secret to authenticate to the IBM Security Verify tenant.'
                ssl: bool
                'Controls whether SSL is used to establish the connection.'
                ssl_truststore: typing.Optional[str]
                'The key database to be used as an SSL truststore. This field is required when "ssl" is ``true``.'
                ssl_key_label: typing.Optional[str]
                'The name of the key which should be used during mutual authentication with the web server.'
                user_endpoint: typing.Optional[str]
                'The versioned endpoint for user requests.'
                authorize_endpoint: typing.Optional[str]
                'The versioned endpoint for authorization requests.'
                authenticators_endpoint: typing.Optional[str]
                'The versioned endpoint for authenticator requests.'
                authnmethods_endpoint: typing.Optional[str]
                'The DEPRECATED versioned endpoint for authentication method requests.'
                factors_endpoint: typing.Optional[str]
                'The versioned endpoint for factors requests.'


            class Java_Database_Connection(typing.TypedDict):
                '''
                jdbc
                '''
                server_name: str
                'The IP address or hostname of the database.'
                port: int
                'The port that the database is listening on.'
                ssl: bool
                'Controls whether SSL is used to establish the connection.'
                user: str
                'The user name used to to authenticate with the database.'
                password: str
                'The password used to to authenticate with the database.'
                type: typing.Optional[str]
                'The Oracle JDBC driver type. Valid types are "thin" and "oci". Only applicable for Oracle connection, this parameter is required for all Oracle connections.'
                service_name: typing.Optional[str]
                'The name of the database service to connect to. Only applicable for Oracle connection, this parameter is required for all Oracle connections.'
                database_name: typing.Optional[str]
                'The name of the database to connect to. Only applicable for DB2 and PostgreSQL connections, this parameter is required for all DB2 and PostgreSQL connections.'
                age_timeout: typing.Optional[int]
                'Amount of time before a physical connection can be discarded by pool maintenance. A value of -1 disables this timeout. Specify a positive integer followed by a unit of time, which can be hours (h), minutes (m), or seconds (s). For example, specify 30 seconds as 30s. You can include multiple values in a single entry. For example, 1m30s is equivalent to 90 seconds. (Default value: "-1")'
                connection_timeout: typing.Optional[int]
                'Amount of time after which a connection request times out. A value of -1 disables this timeout. Specify a positive integer followed by a unit of time, which can be hours (h), minutes (m), or seconds (s). For example, specify 30 seconds as 30s. You can include multiple values in a single entry. For example, 1m30s is equivalent to 90 seconds. (Default value: "30s")'
                max_connections_per_thread: typing.Optional[int]
                'Limits the number of open connections on each thread.'
                max_idle_time: typing.Optional[int]
                'Amount of time after which an unused or idle connection can be discarded during pool maintenance, if doing so does not reduce the pool below the minimum size. A value of -1 disables this timeout. Specify a positive integer followed by a unit of time, which can be hours (h), minutes (m), or seconds (s). For example, specify 30 seconds as 30s. You can include multiple values in a single entry. For example, 1m30s is equivalent to 90 seconds. (Default value: "30m")'
                max_pool_size: typing.Optional[int]
                'Maximum number of physical connections for a pool. A value of 0 means unlimited. (Default value: 50)'
                min_pool_size: typing.Optional[int]
                'Minimum number of physical connections to maintain in the pool. The pool is not pre-populated. Aged timeout can override the minimum.'
                connections_per_thread: typing.Optional[int]
                'Caches the specified number of connections for each thread.'
                connection_purge_policy: typing.Optional[str]
                'Specifies which connections to destroy when a stale connection is detected in a pool. Valid values are: "EntirePool" (When a stale connection is detected, all connections in the pool are marked stale, and when no longer in use, are closed.) "FailingConnectionOnly" (When a stale connection is detected, only the connection which was found to be bad is closed.) "ValidateAllConnections" (When a stale connection is detected, connections are tested and those found to be bad are closed.) (Default value: "EntirePool")'
                connection_reap_time: typing.Optional[str]
                'Amount of time between runs of the pool maintenance thread. A value of "-1" disables pool maintenance. Default value is "3m".'


            class RedisConnection(typing.TypedDict):
                '''
                redis
                '''
                class Server(typing.TypedDict):
                    hostname: str
                    'The IP address or hostname of the Redis server.'
                    port: str
                    'The port that the Redis server is listening on.'

                deployment_model: str
                'The Redis deployment model. Valid values are "standalone" and "sentinel".'
                master_name: str
                'The key used in the redis sentinel node to store the master/slave configuration.'
                hostname: typing.Optional[str]
                'The IP address or hostname of the Redis server. This is only required if the ``deployment_model`` is set as "standalone".'
                port: int
                'The port that the Redis server is listening on.'
                user: typing.Optional[str]
                'The user name to authenticate to the Redis server.'
                password: typing.Optional[str]
                'The password used to to authenticate with the Redis server.'
                ssl: bool
                'Controls whether SSL is used to establish the connection.'
                ssl_trustsotre: typing.Optional[str]
                'The key database to be used as an SSL truststore. Only required if ``ssl`` is set to ``true``.'
                ssl_key_label: typing.Optional[str]
                'The key database to be used as an SSL keystore. Only required if ``ssl`` is set to ``true``.'
                connection_timeout: typing.Optional[int]
                'Amount of time, in seconds, after which a connection to the Redis server times out.'
                idle_timeout: typing.Optional[int]
                'Amount of time, in seconds, after which an established connection will be discarded as idle.'
                max_pool_size: typing.Optional[int]
                'Number of connections which will be pooled.'
                min_pool_size: typing.Optional[int]
                'The minimum number of idle connections in the pool.'
                max_idle_size: typing.Optional[int]
                'The maximum number of idle connections in the pool.'
                io_timeout: typing.Optional[int]
                'Amount of time, in seconds, after which the connection socket will timeout.'
                servers: typing.Optional[typing.List[Server]]
                'Additional Redis servers for this connection.'

            class LDAPConnection(typing.TypedDict):
                '''
                ldap
                '''
                class Server(typing.TypedDict):
                    order: int
                    'The order of precedence for this server.'
                    connection: typing.TypedDict
                    'The connection properties. This dictionary uses the properties from ``LDAPConnection``.'

                hostname: str
                'The IP address or hostname of the LDAP server.'
                port: int
                'The port that the LDAP server is listening on.'
                bind_dn: str
                'The distinguished name to use to bind to the LDAP server.'
                bind_password: str
                'The password for bindDN to use when binding to the LDAP server.'
                ssl: bool
                'Controls whether SSL is used to establish the connection.'
                key_file: str
                'The key database to be used as an SSL truststore.'
                key_label: str
                'The name of the key which should be used during mutual authentication with the LDAP server.'
                timeout: typing.Optional[int]
                'Amount of time, in seconds, after which a connection to the LDAP server times out.'
                servers: typing.Optional[typing.List[Server]]
                'Additional LDAP servers for this connection.'

            class SMTPConnection(typing.TypedDict):
                '''
                smtp
                '''
                hostname: str
                'The IP address or hostname of the SMTP server.'
                port: int
                'The port that the SMTP server is listening on.'
                user: typing.Optional[str]
                'The user name to authenticate to the SMTP server.'
                password: typing.Optional[str]
                'The password used to to authenticate with the SMTP server.'
                ssl: bool
                'Controls whether SSL is used to establish the connection.'
                timeout: typing.Optional[int]
                'Amount of time, in seconds, after which a connection to the SMTP server times out. '

            class VerifyAccessRuntimeConnection(typing.TypedDict):
                '''
                isamruntime
                '''
                bind_dn: str
                'The distinguished name to use to bind to the Verify Access Runtime LDAP server.'
                bind_pwd: str
                'The password for bindDN to use when binding to the Verify Access Runtime LDAP server.'
                ssl: bool
                'Controls whether SSL is used to establish the connection.'
                ssl_truststore: typing.Optional[str]
                'The key database to be used as an SSL truststore. This field is required when "ssl" is true.'
                ssl_key_label: typing.Optional[str]
                'The name of the key which should be used during mutual authentication with the Verify Access runtime LDAP server.'

            class WebServiceConnection(typing.TypedDict):
                '''
                ws
                '''
                url: str
                'The fully qualified URL of the web service endpoint, including the protocol, host/IP, port and path.'
                user: str
                'The user name to authenticate to the web service.'
                password: str
                'The password used to to authenticate with the web service.'
                ssl: bool
                'Controls whether SSL is used to establish the connection.'
                key_file: typing.Optional[str]
                'The key database to be used as an SSL truststore. This field is required when ``ssl`` is true.'
                key_label: typing.Optional[str]
                'The name of the key which should be used during mutual authentication with the web server.'

            name: str
            'The name of the connection.'
            description: typing.Optional[str]
            'A description of the connection.'
            type: str
            'The type of server connection.'
            locked: typing.Optional[bool]
            'Controls whether the connection is allowed to be deleted. If not present, a default of ``false`` will be assumed.'
            properties: typing.Union[IbmsecVerifyConnection, Java_Database_Connection, RedisConnection, LDAPConnection, SMTPConnection, VerifyAccessRuntimeConnection, WebServiceConnection]
            'Connection specific properties.'

        connections: typing.List[Server_Connection]
        'List of server connections to create or update. Properties of individual connections are described in the `_Connection` subclasses.'

    def server_connections(self, config):
        if config.server_connections:
            for connection in config.server_connections:
                if not _remove_server_connection(connection):
                    continue

                method = {"ci": _ci_server_connection,
                          "ldap": _ldap_server_connection,
                          "isamruntime": _runtime_server_connection,
                          "oracle": _jdbc_server_connection,
                          "db2": _jdbc_server_connection,
                          "soliddb": _jdbc_server_connection,
                          "postgresql": _jdbc_server_connection,
                          "smtp": _smtp_server_connection,
                          "ws": _ws_server_connection}.get(connection.type, None)
                if method == None:
                    _logger.error("Unable to create a connection for type {} with config:\n{}".format(
                        connection.type, json.dumps(connection, indent=4)))
                else:
                    rsp = method(connection)
                    if rsp.success == True:
                        _logger.info("Successfully created {} server connection".format(connection.name))
                        self.needsRestart = True
                    else:
                        _logger.error("Failed to create server connection [{}] with config:\n{}".format(
                            connection.name, connection))


    class Template_Files(typing.TypedDict):
        '''
        Example::

                 template_files:
                 - aac/isva_template_files.zip
                 - login.html
                 - 2fa.html

        '''
        template_files: typing.List[str]
        'List of files or zip-files to upload as HTML template pages. Path to files can be relative to the ``ISVA_CONFIG_BASE`` property or fully-qualified file paths.'

    def _strip_base_dir(self, path):
        return path.lstrip(config_base_dir())

    def upload_template_files(self, template_files):
        for file_pointer in template_files:
            rsp = None
            if file_pointer['name'].endswith(".zip"):
                rsp = self.aac.template_files.import_files(file_pointer['path'])
            elif file_pointer.get("type") == "file":
                rsp = self.aac.template_files.create_file(file_pointer['directory'], file_name=file_pointer['name'],
                        contents=file_pointer['contents'])
            else:
                rsp = self.aac.template_files.create_directory(file_pointer['directory'], dir_name=file_pointer['name'])
            if rsp.success == True:
                _logger.info("Successfully created template file {}".format(file_pointer['path']))
            else:
                _logger.error("Failed to create template file {}".format(file_pointer['path']))


    class Mapping_Rules(typing.TypedDict):
        '''
        Examples::

                  mapping_rules:
                  - type: SAML2
                    files:
                    - saml20.js
                    - adv_saml20.js
                  - type: InfoMap
                    files:
                     - mapping_rules/basic_user_email_otp.js
                     - mapping_rules/basic_user_sms_otp.js
                     - mapping_rules/ad_user_mfa.js
                  - type: Fido2
                    files:
                     - mediator.js

        '''

        class Mapping_Rule(typing.TypedDict):
            type: str
            'Type of JavaScript rule to create. Valid values are: "InfoMap", "AuthSVC", "FIDO2", OAUTH","OTP", "OIDC" and "SAML2_0".'
            files: typing.List[str]
            'List of files or directories to upload as JavaScript mapping rules. Path to files can be relative to the ``ISVA_CONFIG_BASE`` property or fully-qualified file paths.'

        mapping_rules: typing.List[Mapping_Rule]
        'List of mapping rule types/files to upload.'

    def upload_mapping_rules(self, _type, mapping_rules):
        for mapping_rule in mapping_rules:
            rsp = self.aac.mapping_rule.create_rule(rule_name=mapping_rule['name'], category=_type, content=mapping_rule['contents'])
            if rsp.success == True:
                _logger.info("Successfully uploaded {} mapping rule".format(mapping_rule['name']))
            else:
                _logger.error("Failed to upload {} mapping rule from [{}]".format(mapping_rule['name'], mapping_rule['path']))


    def upload_files(self, config):
        if config.template_files != None:
            for entry in config.template_files:
                #Convert list of files/directories to flattened list of files
                #include directories if we are a directory
                incDirs = os.path.isdir(os.path.join(config_base_dir(), entry))
                parsed_files = FILE_LOADER.read_files(entry, include_directories=incDirs)
                self._remove_prefix_from_paths(parsed_files, entry)
                self.upload_template_files(parsed_files)
        if config.mapping_rules != None:
            for entry in config.mapping_rules:
                for file_pointer in entry.files:
                    parsed_files = FILE_LOADER.read_files(file_pointer)
                self.upload_mapping_rules(entry.type, parsed_files)


    class Obligations(typing.TypedDict):
        '''
        Example::

                 obligations:
                 - name: "myObligation"
                   description: "Test obligation"
                   type: "Obligation"
                   uri: "urn:ibm:security:obligation:myObligation"
                   parameters:
                   - name: "userid"
                     label: "userid"
                     datatype: "String"

        '''

        class Obligation(typing.TypedDict):
            class Parameter(typing.TypedDict):
                name: str
                'A unique name for the parameter.'
                label: str
                'Label for the parameter. Set it to the value of the name.'
                datatype: str
                'Data type for the parameter. Valid values are "Boolean", "Date", "Double", "Integer", "String", "Time", or "X500Name".'

            class Property(typing.TypedDict):
                key: str
                'A unique key for the property.'
                value: str
                'The value for the property.'

            name: str
            'A unique name for the obligation.'
            description: typing.Optional[str]
            'An optional description of the obligation.'
            uri: str
            'The identifier of the obligation that is used in generated XACML.'
            type: typing.Optional[str]
            'Should be set to "Obligation".'
            type_id: typing.Optional[str]
            'The obligation type id. If not provided, the value will be set to "1", which is the "Enforcement Point" type.'
            parameters: typing.List[Parameter]
            'Array of parameters associated with the obligation.'
            properties: typing.Optional[typing.List[Property]]
            'Array of properties associated with the obligations.'
        
        obligations: typing.List[Obligation]
        'List of access control obligations to create.'

    def obligation_configuration(self, aac_config):
        if aac_config.obligations != None:
            existing = self.aac.access_control.list_obligations().json
            if existing == None: existing = []
            for obligation in aac_config.obligations:
                obg_id = optional_list(filter_list(
                    "obligationURI", obligation.uri, existing))[0].get('id', None)
                rsp = None
                if obg_id:
                    rsp = self.aac.access_control.update_obligation(obg_id, name=obligation.name, 
                            description=obligation.description, obligation_uri=obligation.uri, 
                            type=obligation.type, type_id=obligation.get("type_id", "1"), 
                            parameters=obligation.parameters, properties=obligation.properties)
                    verb = "created" if rsp.success == True else "create"
                else:
                    rsp = self.aac.access_control.create_obligation(name=obligation.name, 
                            description=obligation.description, obligation_uri=obligation.uri, 
                            type=obligation.type, type_id=obligation.get("type_id", "1"), 
                            parameters=obligation.parameters, properties=obligation.properties)
                    verb = "updated" if rsp.success == True else "update"
                if rsp.success == True:
                    _logger.info("Successfully {} {} obligation.".format(verb, obligation.name))
                else:
                    _logger.error("Failed to {} obligation:\n{}\n{}".format(verb, 
                                                                json.dumps(obligation, indent=4), rsp.data))
                return


    class Attributes(typing.TypedDict):
        '''
        Example::

                 attributes:
                   - name: "urn:ibm:demo:transferamount"
                     description: "Verify Demo Transfer Amount"
                     uri: "urn:ibm:demo:transferamount"
                     type:
                       risk: false
                       policy: false
                     datatype: "Double"
                     issuer: ""
                     category: "Action"
                     matcher: "1"
                     storage:
                       session: false
                       behavior: false
                       device: false

        '''

        class Type(typing.TypedDict):
            risk: str
            'True if the attribute is used in risk profiles.'
            policy: str
            'True if the attribute is used in policies.'

        class Storage(typing.TypedDict):
            session: bool
            'True if the attribute is collected in the user session. Session attributes are stored temporarily until the session times out.'
            behavior: bool
            'True if historic data for this attribute is stored in the database and used for behavior-based attribute matching.'
            device: bool
            'True if the attribute is stored when a device is registered as part of the device fingerprint. '

        name: str
        'A unique name for the attribute.'
        description: typing.Optional[str]
        'An optional description of the attribute'
        uri: str
        'The identifier of the attribute that is used in the generated XACML policy.'
        type: Type
        'Type of attribute being used.'
        datatype: str
        'The type of values that the attribute can accept: "String", "Integer", "Double", "Boolean", "Time", "Date", "X500Name".'
        issuer: typing.Optional[str]
        'The name of the policy information point from which the value of the attribute is retrieved.'
        category: str
        'The part of the XACML request that the attribute value comes from: "Subject", "Environment", "Action", "Resource".'
        matcher: str
        'ID of the attribute matcher that is used to compare the value of this attribute in an incoming device fingerprint with an existing device fingerprint of the user.'
        storage: Storage
        'Define where the attribute is stored.'

    def attributes_configuration(self, aac_config):
        if aac_config.attributes != None:
            existing = self.aac.attribute.list_attributes().json
            if existing == None: existing = []
            for attribute in aac_config.attributes:
                methodArgs = copy.deepcopy(attribute)
                attr_id = optional_list(filter_list("uri", attribute.uri, existing))[0].get("id", None)
                for k in ["storage", "type"]: #remap keys "key": {"di": "ct"} -> "key_di": "ct"
                    if k in methodArgs.keys():
                        old = methodArgs.pop(k)
                        for oldKey, value in old.items():
                            methodArgs[k + "_" + old_key] = value

                rsp = None
                if attr_id:
                    rsp = self.aac.attribute.update_attribute(attr_id, **methodArgs)
                    verb = "updated" if rsp.success else "update"
                else:
                    rsp = self.aac.attribute.create_attribute(**methodArgs)
                    verb = "created" if rsp.success == True else "create"
                if rsp.success == True:
                    _logger.info("Successfully {} {} attribute.".format(verb, attribute.name))
                else:
                    _logger.error("Failed to {} attribute:\n{}\n{}".format(verb, json.dumps(
                                                                                    attribute, indent=4), rsp.data))


    def _configure_api_protection_definition(self, definition):
        methodArgs = {"name": definition.name, "description": definition.description, "token_char_set": definition.access_token_char_set,
                "access_token_lifetime": definition.access_token_lifetime, "access_token_length": definition.access_token_length, 
                "authorization_code_lifetime": definition.authorization_code_lifetime, "authorization_code_length": definition.authorization_code_length,
                "refresher_token_length": definition.refresh_token_length, "max_authorization_grant_lifetime": definition.max_authorization_grant_lifetime,
                "pin_length": definition.pin_length, "enforce_single_use_authorization_grant": definition.enforce_single_use_grant, 
                "issue_refresh_token": definition.issue_refresh_token, "enforce_single_access_token_per_grant": definition.single_token_per_grant, 
                "enable_multiple_refresh_tokens_for_fault_tolerance": definition.multiple_refresh_tokens, "pin_policy_enabled": definition.pin_policy, 
                "grant_types": definition.grant_types, "attribute_sources": definition.attribute_sources
            }
        if definition.oidc:
            methodArgs.update({
                "oidc_enabled": True, "iss": definition.oidc.iss, "poc": definition.oidc.poc, "lifetime": definition.oidc.lifetime,
                "alg": definition.oidc.alg, "db": definition.oidc.db, "Cert": definition.oidc.cert
            })
            if definition.oidc.enc:
                methodArgs.update({
                    "enc_enabled": True, "enc_alg": definition.oidc.enc.alg, "enc_enc": definition.oidc.enc.enc
                })
        rsp = self.aac.api_protection.create_definition(**methodArgs)
        if rsp.success == True:
            _logger.info("Successfully created {} API Protection definition".format(definition.name))
        else:
            _logger.error("Failed to create {} API Protection definition with config:\n{}\n{}".format(
                definition.name, json.dumps(definition, indent=4), rsp.data))
        if definition.pre_token_mapping_rule:
            mapping_rule = FILE_LOADER.read_file(definition.pre_token_mapping_rule)
            if len(mapping_rule) != 1:
                _logger.error("Can only specify one Pre-Token Mapping Rule")
            else:
                mapping_rule = mapping_rule[0]
                rsp = self.aac.api_protection.create_rule(name=definition.name + "PreTokenGeneration",
                        category="OAUTH", file_name=mapping_rule["name"], content=mapping_rule['contents'])
                if rsp.success == True:
                    _logger.info("Successfully uploaded {} Pre-Token Mapping Rule".format(definition.name))
                else:
                    _logger.error("Failed to upload {} Pre-Token Mapping Rule".format(definition.name))
        if definition.post_token_mapping_rule:
            mapping_rule = FILE_LOADER.read_file(definition.post_token_mapping_rule)
            if len(mapping_rule) != 1:
                _logger.error("Can only specify one Post-Token Mapping Rule")
            else:
                mapping_rule = mapping_rule[0]
                rsp = self.aac.api_protection.create_rule(name=definition.name + "PostTokenGeneration",
                        category="OAUTH", file_name=mapping_rule['name'], content=mapping_rule['contents'])
                if rsp.success == True:
                    _logger.info("Successfully created {} Post-Token Mapping Rule".format(definition.name))
                else:
                    _logger.error("Failed to create {} Post-Token Mapping Rule".format(definition.name))

    def _configure_api_protection_client(self, definitions, client):
        for definition in definitions:
            if definition['name'] == client.api_definition:
                client.api_definition = definition['id']
                break
        rsp = self.aac.api_protection.create_client(name=client.name, redirect_uri=client.redirect_uri,
                company_name=client.company_name, company_url=client.company_url, contact_person=client.contact_person,
                contact_type=client.contact_type, email=client.email, phone=client.phone, other_info=client.other_info,
                definition=client.api_definition, client_id=client.client_id, client_secret=client.client_secret)
        if rsp.success == True:
            _logger.info("Successfully created {} API Protection client.".format(client.name))
        else:
            _logger.error("Failed to create {} API Protection client with config:\n{}\n{}".format(
                client.name, json.dumps(client, indent=4), rsp.data))

    class API_Protection(typing.TypedDict):
        '''
        Example::

                 api_protection:
                   definitions:
                   - name: "Verify Demo - Open Banking"
                     description: "The Open Banking Definition."
                     tcm_behavior: "NEVER_PROMPT"
                     multiple_refresh_tokens: true
                     access_policy: "Open_Banking"
                     oidc:
                       poc: "https://my.ibmsec.idp.com"
                       iss: "https://my.ibmsec.idp.com"
                       lifetime: 20
                       enabled: true
                       keystore: "rt_profile_keys"
                       cert: "server"
                       alg: "RS256"
                     pre_token_mapping_rule: "Verify Demo - Open Banking_pre_token_generation.js"
                     post_token_mapping_rule: "Verify Demo - Open Banking_post_token_generation.js"
                   - name: "Verify Demo - Client Credentials Authorization Code Consent PSD2"
                     description: "For Fintechs, this is Client Credentials and Authorization Code with consent."
                     grant_types:
                       - "AUTHORIZATION_CODE"
                       - "CLIENT_CREDENTIALS"
                     max_authorization_grant_lifetime: 7200
                   - name: "Verify Demo - Client Credentials AaaS"
                     description: "This is for the AaaS mock server access."
                     tcm_behavior: "NEVER_PROMPT"
                     grant_types:
                       - "CLIENT_CREDENTIALS"
                     access_token_lifetime: 999999999
                   clients:
                   - name: "J.P. Norvill"
                     client_id: "ob_client"
                     client_secret: "hunter2"
                     redirect_uri:
                       - "https://jpnorvill.com/auth"
                       - "http://my.ibmsec.spa.com:19080/auth"
                     company_name: "JPNorvill"
                     contact_type: "TECHNICAL"
                     definition: "Verify Demo - Open Banking"

        '''

        class Definition(typing.TypedDict):

            class OIDC(typing.TypedDict):

                class OIDC_Encoding(typing.TypedDict):
                    enabled: bool
                    'Is encryption enabled for this definition.'
                    alg: str
                    'The key agreement algorithm for encryption. See LMI for choices. Default value is "RSA-OAEP-256".'
                    enc: str
                    'The encryption algorithm. Default value is "A128CBC-HS256".'

                iss: str
                'The issuer identifier of this definition. Should have the prefix "https://".'
                poc: str
                'The Point of Contact URL for this definition, must be a valid URL. Should include the junction portion.'
                lifetime: int
                'The lifetime of the id_tokens issued'
                alg: str
                'The signing algorithm for the JWT, can be any combination of the following: HS/ES/RS 256/384/512, Eg RS256. If HS* signing is used, clients MUST have a client secret to form JWTs. Default value is "RS256"'
                db: str
                'The database containing the signing key for RS/ES signing methods.'
                cert: str
                'The certificate label of the signing key for RS/ES signing methods.'
                enc: OIDC_Encoding
                'JWT encryption config.'
                dynamic_clients: bool
                'Whether or not the client registration endpoint will be enabled for this definition. If not presented in an update or create then a value of ``false`` will be used.'
                issue_secret: bool
                'Whether or not a client secret will be issued to dynamic clients. When this is set to true, a client secret will only be issued to a client registration request which is made by an authenticated user. If not presented in an update or create then a value of ``false`` will be used.'
                oidc_compliant: bool
                'Whether or not the definition should be strictly OIDC Compliant.'
                fapi_compliant: bool
                'Whether or not the definition should be strictly FAPI Compliant. Setting this to ``true`` will automatically set OIDC Compliant to ``true``.'
            
            class Attribute_Source(typing.TypedDict):
                name: str
                'Name the attribute should be exposed as.'
                source: str
                'Reference to the attribute source which should be used to retrieve the value.'

            name: str
            'A unique name for the API protection definition.'
            description: typing.Optional[str]
            'An optional description of the API protection definition.'
            grant_types: typing.List[str]
            'A list of supported authorization grant types. Valid values are "AUTHORIZATION_CODE", "RESOURCE_OWNER_PASSWORD_CREDENTIALS", "CLIENT_CREDENTIALS", "IMPLICIT_GRANT", "SAML_BEARER", "JWT_BEARER", and "DEVICE". At least one must be specified.'
            tcm_behaviour: str
            'Identifies the Trusted Client Manager behavior concerning trusted clients and consent. Specify "ALWAYS_PROMPT" to always prompt the user to provide their consent for a new authorization grant. Specify "NEVER_PROMPT" to allow implicit consent whereby the user is never shown a consent to authorize prompt. Specify "PROMPT_ONCE_AND_REMEMBER" to have the user prompted for consent to authorize when a previous consent for the client with the particular scope is not already stored and to have the Trusted Client Manager store the consent decision when consent is granted so it can be referred to during the next access attempt.'
            access_token_lifetime: typing.Optional[int]
            'Validity of the access token, in seconds. When this lifetime expires, the client cannot use the current access token to access the protected resource. If not provided, the access token lifetime is set to 3600 seconds.'
            access_token_length: typing.Optional[int]
            'Length (characters) of an access token. Maximum value is 500 characters. If not provided, the access token length is set to 20 characters.'
            enforce_single_use_grant: typing.Optional[bool]
            'True if all tokens of the authorization grant should be revoked after an access token is validated. If not provided, the single-use authorization grant is not enforced (``false``).'
            authorization_code_lifetime: typing.Optional[int]
            'Validity period, in seconds, of the authorization code. This field is required if grantTypes includes "AUTHORIZATION_CODE". If not provided, the authorization code lifetime is set to 300 seconds.'
            authorization_code_length: typing.Optional[int]
            'Length of an authorization code. This field is required if grantTypes includes "AUTHORIZATION_CODE". Maximum value is 500 characters. If not provided, the authorization code length is set to 30 characters.'
            issue_refresh_token: typing.Optional[int]
            'True if a refresh token should be issued to the client. This option is only applicable when grantTypes includes "AUTHORIZATION_CODE" or "RESOURCE_OWNER_PASSWORD_CREDENTIALS". Otherwise, include this field with a value of ``false``. If not provided, it is set to ``true``.'
            refresh_token_length: typing.Optional[int]
            'Length of a refresh token. Maximum value is 500 characters.If not provided, the refresh token length is set to 40 characters.'
            max_authorization_grant_lifetime: typing.Optional[int]
            'The maximum duration of a grant, in seconds, where the resource owner authorized the client to access the protected resource. The maximum value is 604800 seconds; the minimum is 1. The value for this lifetime must be greater than the values specified for the authorization code and access token lifetimes. If not provided, the value is set to 604800.'
            single_token_per_grant: typing.Optional[bool]
            'True if previously granted access tokens should be revoked after a new access token is generated by presenting the refresh token to the authorization server. Applicable if issueRefreshToken is ``true``. Otherwise, include this field with a value of ``false``. If not provided, the single access token per authorization grant is enforced (``true``).'
            multiple_refresh_tokens: typing.Optional[bool]
            'True if multiple refresh tokens are stored so that the old refresh token is valid until the new refresh token is successfully delivered. Applicable if issueRefreshToken is ``true``. Otherwise, include this field with a value of ``false``. If not provided, the default value is ``false``.'
            pin_policy: typing.Optional[bool]
            'True if the refresh token will be further protected with a PIN provided by the API protection client. Applicable when issueRefreshToken is ``true``. Otherwise, include this field with a value of ``false``. If not provided, the PIN policy is disabled (``false``).'
            pin_length: typing.Optional[int]
            'The length of a PIN. Applicable when pinPolicyEnabled is true. Maximum value is 12 characters. Minimum value is 3 characters. If not provided, the PIN length is set to 4 characters.'
            token_char_set: typing.Optional[str]
            'String of characters that can be used to generate tokens. If not provided, the value will be set to alphanumeric character set, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz". The maximum number of token characters that can be specified is 200.'
            oidc: typing.Optional[OIDC]
            'The OIDC configuration for this API protection definition.'
            attribute_sources: typing.Optional[typing.List[Attribute_Source]]
            'Array of configured attribute sources to use in id_token generation and userinfo requests.'
            pre_token_mapping_rule: typing.Optional[str]
            'Path to file to upload as JavaScript pre-token rule.'
            post_token_mapping_rule: typing.Optional[str]
            'Path to file to upload as JavaScript post-token rule.'

        class Client(typing.TypedDict):
            name: str
            'A meaningful name to identify this API protection client.'
            defintition: str
            'The name of the related API protection definition which owns and defines this client. A client registration can only belong to one definition, but a definition can own many client registrations. The definition cannot be modified.'
            redirect_uri: typing.Optional[str]
            'The redirect URI to use for this client. If omitted, the value is set to null.'
            company_name: typing.Optional[str]
            'Name of the company associated with this client.'
            comapny_url: typing.Optional[str]
            'URL for the company associated with this client. If omitted, the value is set to null.'
            contact_person: typing.Optional[str]
            'Name of the contact person for this client. If omitted, the value is set to null.'
            contact_type: typing.Optional[str]
            'Further describes the contact. Specify one of the following values: "TECHNICAL", "SUPPORT", "ADMINISTRATIVE", "BILLING", or "OTHER". If omitted, the value is set to null.'
            email: typing.Optional[str]
            'The email address of the contact person for this client. If omitted, the value is set to null.'
            phone: typing.Optional[str]
            'The telephone number of the contact person for this client. Input must be completely numeric with no parenthesis or dashes. If omitted, value is set to null.'
            other_info: typing.Optional[str]
            'Other information about the client contact. If omitted, the value is set to null.'
            client_id: typing.Optional[str]
            'A unique OAUTH client identifier to identify this client to the authorization server. It is sent in the token endpoint request to perform client authentication. If omitted, a random and unique alphanumeric string is generated and used as the client identifier.'
            client_secret: typing.Optional[str]
            'A string that identifies this client as confidential and serves as this client\'s secret. The client secret mechanism is a means of authorizing a client. Applications requesting an access token must know the client secret in order to gain the token. If omitted, the value is set to null and the client is considered a public client.'
            require_pkce: typing.Optional[bool]
            'Whether or not this client must perform proof of key exchange when performing an authorization code flow. This follows RFC 7636. Defaults to false.'
            encryption_db: typing.Optional[str]
            'The database containing the JWT encryption key. Not required for dir/AES key wrap / AES GCM key wrap.'
            encryption_cert: typing.Optional[str]
            'The certificate label of the JWT encryption key. Not required for dir/AES key wrap / AES GCM key wrap.'
            jwks_uri: typing.Optional[str]
            'URI which is the location that a clients published JWK set. Used in validating client assertions, request JWTs and for encrypting id_tokens.'
            introspect_with_secret: typing.Optional[bool]
            'Does this client require a client secret when introspecting. When not provided defaults to ``true``.'
            ext_properties: typing.Optional[typing.TypedDict]
            'Dynamic Client information. This is free form JSON.'


        definitions: typing.Optional[typing.List[Definition]]
        'List of OIDC defintions to create.'
        clients: typing.Optional[typing.List[Client]]
        'List of OIDC clients to create.'

    def api_protection_configuration(self, aac_config):
        if aac_config.api_protection != None and aac_config.api_protection.definitions != None:
            for definition in aac_config.api_protection.definitions:
                self._configure_api_protection_definition(definition)

            if aac_config.api_protection.clients != None:
                definitions = self.aac.api_protection.list_definitions()
                for client in aac_config.api_protection.clients:
                    self._configure_api_protection_client(definitions, client)


    def _configure_mechanism(self, mechTypes, existing_mechanisms, mechanism):
        typeId = optional_list(filter_list('type', mechanism.type, mechTypes))[0].get('id', None)
        if not typeId:
            _logger.error("Mechanism [{}] specified an invalid type, skipping.".format(mechanism))
            return
        props = None
        if mechanism.properties != None and isinstance(mechanism.properties, list):
            props = []
            for e in mechanism.properties: 
                props += [{"key": k, "value": v} for k, v in e.items()]
        old_mech = optional_list(filter_list('uri', mechanism.uri, existing_mechanisms))[0]
        rsp = None
        if old_mech:
            rsp = self.aac.authentication.update_mechanism(id=old_mech['id'], description=mechanism.description, 
                    name=mechanism.name, uri=mechanism.uri, type_id=typeId, predefined=old_mech['predefined'], 
                    properties=props, attributes=mechanism.attributes)
        else:
            rsp = self.aac.authentication.create_mechanism(description=mechanism.description, name=mechanism.name,
                    uri=mechanism.uri, type_id=typeId,  properties=props, attributes=mechanism.attributes)
        if rsp.success == True:
            _logger.info("Successfully set configuration for {} mechanism.".format(mechanism.name))
            self.needsRestart = True
        else:
            _logger.error("Failed to set configuration for {} mechanism with:\n{}\n{}".format(
                mechanism.name, json.dumps(mechanism, indent=4), rsp.data))

    def _configure_policy(self, existing_policies, policy):
        rsp = None
        old_policy = optional_list(filter_list('uri', policy.uri, existing_policies))[0]
        if old_policy:
            rsp = self.aac.authentication.update_policy(old_policy['id'], name=policy.name, policy=policy.policy, uri=policy.uri,
                    description=policy.description, predefined=old_policy['predefined'], enabled=policy.enabled)
        else:
            rsp = self.aac.authentication.create_policy(name=policy.name, policy=policy.policy, uri=policy.uri, description=policy.description,
                    enabled=policy.enabled)
        if rsp.success == True:
            _logger.info("Successfully set configuration for {} policy".format(policy.name))
            self.needsRestart = True
        else:
            _logger.error("Failed to set configuration for {} policy with:\n{}\n{}".format(
                policy.name, json.dumps(policy, indent=4), rsp.data))

    class Authentication(typing.TypedDict):
        '''
        Example::

                  authentication:
                    mechanisms:
                    - name: "Verify Demo - QR Code Initiate"
                      uri: "urn:ibm:security:authentication:asf:mechanism:qr_code_initiate"
                      description: "InfoMap to initiate the QR login"
                      type: "InfoMapAuthenticationName"
                      properties:
                      - mapping_rule: "InfoMap_QRInitiate"
                      - template_file: ""
                    - name: "Verify Demo - QR Code Response"
                      uri: "urn:ibm:security:authentication:asf:mechanism:qr_code_response"
                      description: "InfoMap to use the LSI for QR login"
                      type: "InfoMapAuthenticationName"
                      properties:
                      - mapping_rule: "InfoMap_QRResponse"
                      - template_file: ""
                    - name: "Username Password"
                      uri: "urn:ibm:security:authentication:asf:mechanism:password"
                      description: "Username password authentication"
                      type: "Username Password"
                      properties:
                      - usernamePasswordAuthentication.ldapHostName: "openldap"
                      - usernamePasswordAuthentication.loginFailuresPersistent: "false"
                      - usernamePasswordAuthentication.ldapBindDN: !secret default/isva-secrets:ldap_bind_dn
                      - usernamePasswordAuthentication.maxServerConnections: "16"
                      - usernamePasswordAuthentication.mgmtDomain: "Default"
                      - usernamePasswordAuthentication.sslEnabled: "true"
                      - usernamePasswordAuthentication.ldapPort: "636"
                      - usernamePasswordAuthentication.sslTrustStore: "lmi_trust_store"
                      - usernamePasswordAuthentication.userSearchFilter: "usernamePasswordAuthentication.userSearchFilter"
                      - usernamePasswordAuthentication.ldapBindPwd: !secret default/isva-secrets:ldap_bind_pwd
                      - usernamePasswordAuthentication.useFederatedDirectoriesConfig: "false"
                    - name: "TOTP One-time Password"
                      uri: "urn:ibm:security:authentication:asf:mechanism:totp"
                      description: "Time-based one-time password authentication"
                      type: "TOTP One-time Password"
                      properties:
                      - otp.totp.length: "6"
                      - otp.totp.macAlgorithm: "HmacSHA1"
                      - otp.totp.oneTimeUseEnabled: "true"
                      - otp.totp.secretKeyAttributeName: "otp.hmac.totp.secret.key"
                      - otp.totp.secretKeyAttributeNamespace: "urn:ibm:security:otp:hmac"
                      - otp.totp.secretKeyUrl: "otpauth://totp/Example:@USER_NAME@?secret=@SECRET_KEY@&issuer=Example"
                      - otp.totp.secretKeyLength: "32"
                      - otp.totp.timeStepSize: "30"
                      - otp.totp.timeStepSkew: "10"
                    - name: "reCAPTCHA Verification"
                      uri: "urn:ibm:security:authentication:asf:mechanism:recaptcha"
                      description: "Human user verification using reCAPTCHA Version 2.0."
                      type: "ReCAPTCHAAuthenticationName"
                      properties:
                      - reCAPTCHA.HTMLPage: "/authsvc/authenticator/recaptcha/standalone.html"
                        reCAPTCHA.apiKey: !secret default/isva-secrets:recaptcha_key
                    - name: "End-User License Agreement"
                      uri: "urn:ibm:security:authentication:asf:mechanism:eula"
                      description: "End-user license agreement authentication"
                      type: "End-User License Agreement"
                      properties:
                      - eulaAuthentication.acceptIfLastAcceptedBefore: "true"
                      - eulaAuthentication.alwaysShowLicense: "false"
                      - eulaAuthentication.licenseFile: "/authsvc/authenticator/eula/license.txt"
                      - eulaAuthentication.licenseRenewalTerm: "0"
                    - name: "FIDO Universal 2nd Factor"
                      uri: "urn:ibm:security:authentication:asf:mechanism:u2f"
                      description: "FIDO Universal 2nd Factor Token Registration and Authentication"
                      type: "U2FName"
                      properties:
                      - U2F.attestationSource: ""
                      - U2F.attestationType: "None"
                      - U2F.appId: "www.myidp.ibm.com"
                      - U2F.attestationEnforcement: "Optional"

                    policies:
                    - name: "Verify Demo - Initiate Generic Message Demo Policy"
                      uri: "urn:ibm:security:authentication:asf:verify_generic_message"
                      description: "IBM MFA generic message policy."
                      policy: "<Policy xmlns=\"urn:ibm:security:authentication:policy:1.0:schema\" PolicyId=\"urn:ibm:security:authentication:asf:verify_generic_message\"><Description>IBM MFA generic message policy.</Description><Step id=\"id15342210896710\" type=\"Authenticator\"><Authenticator id=\"id15342210896711\" AuthenticatorId=\"urn:ibm:security:authentication:asf:mechanism:generic_message\"/></Step><Step id=\"id15342211135160\" type=\"Authenticator\"><Authenticator id=\"id15342211135161\" AuthenticatorId=\"urn:ibm:security:authentication:asf:mechanism:mmfa\"><Parameters><AttributeAssignment AttributeId=\"contextMessage\"><AttributeDesignator AttributeId=\"message\" Namespace=\"urn:ibm:security:asf:response:token:attributes\" Source=\"urn:ibm:security:asf:scope:session\" DataType=\"String\"/></AttributeAssignment><AttributeAssignment AttributeId=\"mode\"><AttributeValue DataType=\"String\">Initiate</AttributeValue></AttributeAssignment><AttributeAssignment AttributeId=\"policyURI\"><AttributeValue DataType=\"URI\">urn:ibm:security:authentication:asf:verify_mmfa_response_fingerprint</AttributeValue></AttributeAssignment><AttributeAssignment AttributeId=\"username\"><AttributeDesignator AttributeId=\"username\" Namespace=\"urn:ibm:security:asf:response:token:attributes\" Source=\"urn:ibm:security:asf:scope:session\" DataType=\"String\"/></AttributeAssignment></Parameters></Authenticator></Step></Policy>"
                    - name: "Verify Demo - QR Code Initiate"
                      uri: "urn:ibm:security:authentication:asf:qrlogin_initiate"
                      description: "Login without a password - use your phone and scan a QR code!"
                      policy: "<Policy xmlns=\"urn:ibm:security:authentication:policy:1.0:schema\" PolicyId=\"urn:ibm:security:authentication:asf:qrlogin_initiate\"><Description>Login without a password - use your phone and scan a QR code!</Description><Step id=\"id15033758674560\" type=\"Authenticator\"><Authenticator id=\"id15033758674561\" AuthenticatorId=\"urn:ibm:security:authentication:asf:mechanism:qr_code_initiate\"/></Step></Policy>",
                    - name: "Verify Demo - QR Code Response"
                      uri: "urn:ibm:security:authentication:asf:qrlogin_response"
                      description: "Login without a password - use your phone and scan a QR code!"
                      policy: "<Policy xmlns=\"urn:ibm:security:authentication:policy:1.0:schema\" PolicyId=\"urn:ibm:security:authentication:asf:qrlogin_response\"><Description>qrlogin_response<\/Description><Step id=\"id15033758436320\" type=\"Authenticator\"><Authenticator id=\"id15033758436321\" AuthenticatorId=\"urn:ibm:security:authentication:asf:mechanism:qr_code_response\"\/><\/Step><\/Policy>"
                    - name: "FIDO U2F Authenticate"
                      uri: "urn:ibm:security:authentication:asf:u2f_authenticate"
                      description: "FIDO Universal 2nd Factor Token Authentication"
                      policy: "<Policy xmlns=\"urn:ibm:security:authentication:policy:1.0:schema\" PolicyId=\"urn:ibm:security:authentication:asf:u2f_authenticate\"><Description>FIDO Universal 2nd Factor Token Authentication</Description><Step id=\"Step_1\" type=\"Authenticator\"><Authenticator id=\"Auth_1\" AuthenticatorId=\"urn:ibm:security:authentication:asf:mechanism:u2f\"><Parameters><AttributeAssignment AttributeId=\"mode\"><AttributeValue DataType=\"String\">Authenticate</AttributeValue></AttributeAssignment><AttributeAssignment AttributeId=\"username\"><AttributeDesignator AttributeId=\"username\" Namespace=\"urn:ibm:security:asf:request:parameter\" Source=\"urn:ibm:security:asf:scope:request\" DataType=\"String\"/></AttributeAssignment></Parameters></Authenticator></Step><Actions><Action On=\"null\" type=\"null\"><AttributeAssignments/></Action></Actions></Policy>"

        '''

        class Mechanism(typing.TypedDict):

            class Attribute(typing.TypedDict):
                selector: str
                'Name of a registry attribute to obtain.'
                namespace: str
                'Authentication service namespace of "name".'
                name: str
                'Authentication service context attribute.'

            name: str
            'A unique name for the authentication mechanism.'
            description: typing.Optional[str]
            'An optional description of the authentication mechanism.'
            uri: str
            'The unique resource identifier of the authentication mechanism.'
            type: str
            'Type of mechanism to create, eg: "InfoMapAuthenticationName", "Username Password" or "Mobile Multi Factor Authenticatior".'
            properties: typing.List[typing.TypedDict]
            'List of properties to configure for mechanism. The property names are different for rach of the mechanism types.'
            attributes: typing.Optional[typing.List[Attribute]]
            'List of attribute to add from the request context.'

        class Policy(typing.TypedDict):

            name: str
            'Specify a unique name for the authentication policy.'
            description: str
            'Description of the authentication policy.'
            uri: str
            'Specify a unique resource identifier for the authentication policy.'
            dialect: typing.Optional[str]
            'Authentication policy specification used to format the authentication policy. The only valid value is "urn:ibm:security:authentication:policy:1.0:schema".'
            policy: str
            'Configured policy content that uses the specified authentication policy dialect.'
            enabled: bool
            'True if the policy is enabled and invocable at runtime. Set to false to disable the policy. If the policy is disabled it cannot be used by context based access.'

        mechanisms: typing.Optional[typing.List[Mechanism]]
        'List of authentication mechanism to create or update.'
        policies: typing.Optional[typing.List[Policy]]
        'List of authentication policies to create or update.'


    def authentication_configuration(self, aac_config):
        if aac_config.authentication != None:
            if aac_config.authentication.mechanisms != None:
                mech_types = self.aac.authentication.list_mechanism_types().json
                if mech_types == None:
                    _logger.error("Faield to get list of mechanism types")
                    return
                existing_mechanisms = self.aac.authentication.list_mechanisms().json
                if existing_mechanisms == None:
                    existing_mechanisms = []
                for mechanism in aac_config.authentication.mechanisms:
                    self._configure_mechanism(mech_types, existing_mechanisms, mechanism)
            if self.needsRestart == True:
                deploy_pending_changes() # Mechanisms must be deployed before they are usable in policies
                self.needsRestart = False
            if aac_config.authentication.policies != None:
                existing_policies = self.aac.authentication.list_policies().json
                if existing_policies == None:
                    existing_policies = []
                for policy in aac_config.authentication.policies:
                    self._configure_policy(existing_policies, policy)


    class Mobile_Multi_Factor_Authentication(typing.TypedDict):
        '''
        Example::

                 mmfa:
                   client_id: "IBMVerify"
                   hostname: "https://www.myidp.ibm.com"
                   port: 444
                   options: "ignoreSslCerts=true"
                   junction: "/mga"
                   discovery_mechanisms:
                   - "urn:ibm:security:authentication:asf:mechanism:totp"
                   - "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:user_presence"
                   - "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:fingerprint"

        '''
        class Endpoints(typing.TypedDict):
            details_url: str
            'The discovery endpoint included in the registration QR code.'
            enrollment_endpoint: str
            'The enrollment endpoint returned from the discovery endpoint.'
            hotp_shared_secret_endpoint: str
            'The HOTP shared secret endpoint returned from the discovery endpoint.'
            totp_shared_secret_endpoint: str
            'The TOTP shared secret endpoint returned from the discovery endpoint.'
            qrlogin_endpoint: str
            'The QR Code login endpoint returned from the discovery endpoint.'
            token_endpoint: str
            'The OAuth token endpoint returned from the discovery endpoint.'
            authntrxn_endpoint: str
            'The SCIM Transaction endpoint returned from the discovery endpoint.'
            mobile_endpoint_prefix: str
            'The prefix of the runtime endpoint that is constructed and saved as the requestUrl of a transaction. '

        client_id: str
        'The OAuth client ID required for the MMFA service.'
        hostname: typing.Optional[str]
        'The hostname of the MMFA endpoint URI. Protocol used will be https. Must be configured if endpoints is not included'
        port: typing.Optional[int]
        'The port of the MMFA endpoint URI. Must be configured if endpoints is not included.'
        junction: typing.Optional[str]
        'The junction of the MMFA endpoint URI. Must be configured if endpoints is not included.'
        options: typing.Optional[str]
        'A list of configurable key-value pairs to be presented in the QR code. Recommended formatting "key=value,key=value".'
        endpoints: typing.Optional[Endpoints]
        'An object containing the endpoints returned from the registration QR code or the discovery endpoint. If configured, overwrites hostname, port, and junction configuration.'
        discovery_mechanisms: typing.Optional[typing.List[str]]
        'A list of authentication mechanism URIs to be included in the discovery endpoint response.'

    def mmfa_configuration(self, aac_config):
        if aac_config.mmfa != None:
            methodArgs = copy.deepcopy(aac_config.mmfa)
            if aac_config.api_protection != None and aac_config.api_protection.clients != None:
                api_clients = self.aac.api_protection.list_clients().json
                for client in api_clients:
                    if client['name'] == aac_config.mmfa.client_id:
                        methodArgs['client_id'] = client['clientId']
                        break
            endpoints = methodArgs.pop("endpoints", None)
            if endpoints:
                methodArgs.update({**endpoints})
            rsp = self.aac.mmfaconfig.update(**methodArgs)
            if rsp.success == True:
                _logger.info("Successfully updated MMFA configuration")
                self.needsRestart = True
            else:
                _logger.error("Failed to update MMFA configuration with:\n{}\n{}".format(
                    json.dumps(aac_config.mmfa, indent=4), rsp.data))


    def _upload_metadata(self, metadata):
        metadata_list = FILE_LOADER.read_files(metadata)
        for metadata_file in metadata_list:
            rsp = self.aac.fido2_config.create_metadata(filename=metadata_list['path'])
            if rsp.success == True:
                _logger.info("Successfully created {} FIDO metadata".foramt(metadata_file['name']))
            else:
                _logger.error("Failed to create {} FIDO metadata".format(metadata_file["name"]))


    def _create_mds(self, mds):
        rsp = self.aac.fido2_config.create_metadata_service(**mds)
        if rsp.success == True:
            _logger.info("Successfully created {} FIDO metadata service".foramt(mds.url))
        else:
            _logger.error("Failed to create FIDO metadata service:\n{}\n{}".format(
                                                                json.dumps(mds, indent=4), rsp.data))


    def _upload_mediator(self, mediator):
        mediator_list = FILE_LOADER.read_files(mediator)
        for mediator_rule in mediator_list:
            rsp = self.aac.fido2_config.create_mediator(name=mediator_rule['name'], filename=mediator_rule['path'])
            if rsp.success == True:
                _logger.info("Successfully created {} FIDO2 Mediator".format(mediator_rule['name']))
            else:
                _logger.error("Failed to create {} FIDO2 Mediator".format(mediator_rule['name']))

    def _create_relying_party(self, rp):
        rp_metadata = rp.get("metadata", []) # Need empty list instead of None
        if rp.metadata:
            metadata_list = optional_list(self.aac.fido2_config.list_metadata().json)
            for pos, metadata in enumerate(rp.metadata):
                for uploaded_metadata in metadata_list:
                    if uploaded_metadata['filename'] == metadata:
                        rp_metadata[pos] = uploaded_metadata['id']
                        break
        if rp.use_all_metadata:
            metadata_list = optional_list(self.aac.fido2_config.list_metadata().json)
            for uploaded_metadata in metadata_list:
                rp_metadata += [uploaded_metadata['id']]

        if rp.mediator:
            medaitor_list = self.aac.fido2_config.list_mediator().json
            for mediator in mediator_list:
                if mediator['fileName'] == rp.mediator:
                    rp.mediator = mediator['id']
                    break
        methodArgs = {
                "name": rp.name,
                "rp_id": rp.rp_id,
                "origins": rp.origins,
                "metadata_set": rp_metadata,
                "metadata_soft_fail": rp.metadata_soft_fail,
                "mediator_mapping_rule_id": rp.mediator,
                "relying_party_impersonation_group": rp.impersonation_group
            }
        if rp.attestation:
            methodArgs.update({
                "attestation_statement_types": rp.attestation.statement_types,
                "attestation_statement_formats": rp.attestation.statement_formats,
                "attestation_public_key_algorithms": rp.attestation.public_key_algorithms
            })
            if rp.android:
                methodArgs.update({
                        "attestation_android_safetynet_max_age": rp.attestation.android.max_age,
                        "attestation_android_safetynet_clock_skew": rp.attestation.android.clock_skew
                    })
        rsp = self.aac.fido2_config.create_relying_party(**methodArgs)
        if rsp.success == True:
            _logger.info("Successfully created {} FIDO2 Relying Party".format(rp.name))
        else:
            _logger.error("Failed to create {} FIDO2 Relying Party with configuration:\n{}\n{}".format(rp.name,
                json.dumps(rp, indent=4), rsp.data))


    class Fast_Identity_Online2(typing.TypedDict):
        '''
        Example::

                fido2:
                  relying_parties:
                  - name: "fidointerop.securitypoc.com"
                    rp_id: "fidointerop.securitypoc.com"
                    origins:
                    - "https://fidointerop.securitypoc.com"
                    - "urn:ibm:security:verify:app:namespace"
                    use_all_metadata: true
                    metadata_soft_fail: false
                    metadata_services:
                    - url: "https://mds3.fidoalliance.org"
                      truststore: "rt_profile_keys"
                      jws_truststore: "fido_mds_certs"
                    mediator: "fido2_mediator_verifysecuritypoc.js"
                    attestation:
                      statement_types:
                      - "basic"
                      - "self"
                      - "attCA"
                      - "anonCA"
                      - "none"
                      statement_formats:
                      - "fido-u2f"
                      - "packed"
                      - "self"
                      - "android-key"
                      - "android-safetynet"
                      - "tpm"
                      - "none"
                  metadata:
                    metadata:
                    - "fido2/metadata"
                    metadata_services:

        '''
        class Relying_Party(typing.TypedDict):
            class Attestation:
                statement_types: typing.Optional[typing.List[str]]
                'List of attestation types to permit.'
                statement_formats: typing.Optional[typing.List[str]]
                'List of attestation formats to permit.'
                public_key_algorithms: typing.Optional[typing.List[str]]
                'List of COSE algorithm identifiers to permit.'

            class Android:
                max_age: int
                'Maximum age of attestation signature.'
                clock_skew: int
                'Maximum allowed clock skew in signed attestation attributes.'

            name: str
            'Name of the relying party.'
            rp_id: str
            'URI of the relying party base domain.'
            origins: typing.List[str]
            'List of permitted origins. These should be valid sub-domains of the ``rp_id``.'
            metadata: typing.Optional[typing.List[str]]
            'List of metadata documents to enable for this relying party.'
            mds: typing.Optional[str]
            'List of metadata services to enable for this relying party.'
            use_all_metadata: typing.Optional[bool]
            'Use all available metadata documents for this relying party.'
            mediator: typing.Optional[str]
            'Mediator mappign rule to configure for this relying party.'
            impersonation_group: typing.Optional[str]
            'Group used to permit admin operations for this relying party.'
            attestation: typing.Optional[Attestation]
            'Attestation properties permitted for this relying party.'
            android: typing.Optional[Android]
            'Androind attestation specific configuration.'

        class Metadata(typing.TypedDict):

            class Metadata_Service(typing.TypedDict):
                class Header(typing.TypedDict):
                    name: str
                    'The name of the HTTP header.'
                    value: str
                    'The value of the HTTP header.'

                url: str
                'Address of the metadata service.'
                retry_interval: typing.Optional[int]
                'When the lifetime of a downloaded metadata has expired and a request to retrieve the new metadata fails, this defines the wait interval (in seconds) before retrying the download. If not specified the default value of 3600 seconds will be used. A value of 0 will result in a retry on each attestation validation.'
                jws_truststore: typing.Optional[str]
                'The name of the JWS verification truststore. The truststore contains the certificate used to verify the signature of the downloaded metadata blob. If not specified the SSL trust store or the trust store configured in the HTTPClientV2 advanced configuration will be used.'
                truststore: typing.Optional[str]
                'The name of the truststore to use. The truststore has a dual purpose. Firstly it is used when making a HTTPS connection to the Metadata Service. Secondly if the jwsTruststore is not specified it must contain the certificate used to verify the signature of the downloaded metadata blob. If not specified and a HTTPS connection is specified, the trust store configured in the HTTPClientV2 advanced configuration will be used.'
                username: typing.Optional[str]
                'The basic authentication username. If not specified BA will not be used.'
                password: typing.Optional[str]
                'The basic authentication password. If not specified BA will not be used.'
                keystore: typing.Optional[str]
                'The client keystore. If not specified client certificate authentication will not be used.'
                certificate: typing.Optional[str]
                'The client key alias. If not specified client certificate authentication will not be used.'
                protocol: typing.Optional[str]
                'The SSL protocol to use for the HTTPS connection. Valid values are TLS, TLSv1, TLSv1.1 and TLSv1.2. If not specified the protocol configured in the HTTPClientV2 advanced configuration will be used.'
                timeout: typing.Optional[int]
                'The request timeout in seconds. A value of 0 will result in no timeout. If not specified the connect timeout configured in the HTTPClientV2 advanced configuration will be used.'
                proxy: typing.Optional[str]
                'The URL of the proxy server used to connect to the metadata service (including the protocol).'
                headers: typing.Optional[typing.List[Header]]
                'A list of HTTP headers to be added to the HTTP request when retrieving the metadata from the service. '

            metadata_services: typing.Optional[typing.List[Metadata_Service]]
            'List of metadata services to enable for the relying party.'
            metadata: typing.Optional[typing.List[str]]
            'List of metadata documents to enable for the relying party.'

        mediators: typing.Optional[typing.List[str]]
        'JavaScript files to upload as FIDO2 mediators.'
        metadata: typing.Optional[Metadata]
        'Files to upload as static FIDO2 metadata documents.'
        relying_parties: typing.Optional[typing.List[Relying_Party]]
        'List of relying parties to configure.'


    def fido2_configuration(self, aac_config):
        if aac_config.fido2 != None:
            fido2 = aac_config.fido2
            if fido2.metadata != None:
                for metadata in fido2.metadata.get("metadata", []):
                    self._upload_metadata(metadata)
                for mds in fido2.metadata.get("metadata_services", []):
                    self._create_mds(mds)
            if fido2.mediators != None:
                for mediator in fido2.mediators:
                    self._upload_mediator(mediator)
            if fido2.relying_parties != None:
                for rp in fido2.relying_parties:
                    self._create_relying_party(rp)


    class Runtime_Configuration(typing.TypedDict):
        '''
        Example::

                runtime_properties:
                  users:
                  - name: "easuser"
                    password: !secret default/isva-secrets:runtime_password
                    groups:
                    - "scimAdmin"
                    - "fidoAdmin"
                  tuning_parameters:
                  - name: "https_proxy_host"
                    value: "http://my.proxy"
                  - name: "https_proxy_port"
                    value: "3128"
                  endpoints:
                  - interface: "1.1"
                    address: "192.168.42.102"
                    port: 444
                    ssl: true
                  - interface: "1.2"
                    dhcp4: true
                    dhcp6: false
                    port: 443
                    ssl: true

        '''

        class User(typing.TypedDict):
            name: str
            'Name of the user to create or update.'
            password: str
            'The password for the new user. This can contain any ASCII characters.'
            groups: typing.Optional[typing.List[str]]
            'A list of groups the new user will belong to.'

        class Group(typing.TypedDict):
            name: str
            'Name of the group to create or update.'
            users: typing.Optional[typing.List[str]]
            'List of users to add to the group.'

        class Endpoint(typing.TypedDict):
            interface: str
            'The interface the runtime endpoint will listen on.'
            address: typing.Optional[str]
            'The static address that the runtime endpoint will listen on.'
            dhcp4: typing.Optional[bool]
            'Endpoint should listen on the DHCP IPv4 address for the given interface.'
            dhcp6: typing.Optional[bool]
            'Endpoint should listen on the DHCP IPv6 address for the given interface.'
            port: int
            'Port that endpoint will listen on.'
            ssl: bool
            'Endpoint should use SSL encryption for connections.'

        class Runtime_Tuning_Parameter(typing.TypedDict):
            name: str
            'The tuning parameter to set.'
            value: str
            'The new value for the specified parameter.'

        users: typing.Optional[typing.List[User]]
        'List of users to add/update in the AAC/Federation runtime user registry. Users are created before groups, so if you are creating a user and a group in the same autoconf; then only add you user to the list of users when creating the group.'
        groups: typing.Optional[typing.List[Group]]
        'List of groups to add/update in the AAC/Federation runtime user registry'
        tuning_parameters: typing.Optional[typing.List[Runtime_Tuning_Parameter]]
        'List of AAC/Federation runtime JVM tuning parameters.'
        endpoints: typing.Optional[typing.List[Endpoint]]
        'List of http(s) endpoints that the AAC/Federation runtime is listenting on.'

    def runtime_configuration(self, aac_config):
        if aac_config.runtime_properties:
            for parameter in aac_config.runtime_properties.get("tuning_parameters", []):
                rsp = self.aac.runtime_parameters.update_parameter(
                        parameter=parameter.name, value=parameter.value)
                if rsp.success == True:
                    _logger.info("Successfully updated {} runtime tuning parameter.".format(
                                                                                    parameter.name))
                else:
                    _logger.error("Failed to update parameter:\n{}\n{}".format(
                                                            json.dumps(parameter, ident=4), rsp.data))
            if aac_config.runtime_properties.endpoints: # Readable name to Verify Access uuid
                iface_cfg = optional_list(self.factory.get_system_settings().interfaces.list_interfaces().json)
                for endpoint in aac_config.runtime_properties.endpoints:
                    iface_address_uuids = ""
                    for iface in iface_cfg:
                        if iface['name'] == endpoint.interface:
                            iface_address_uuids += iface['uuid']
                            if endpoint.dhcp4 == True:
                                iface_address_uuids += ".dhcp.ipv4"
                            elif endpoint.dhcp6 == True:
                                iface_address_uuids += ".dhcp.ipv6"
                            elif endpoint.address:
                                for address in iface["ipv4"].get("addresses"):
                                    if address['address'] == endpoint.address:
                                        iface_address_uuids += "." + address['uuid']
                                        break
                    rsp = self.aac.runtime_parameters.add_listening_interface(
                                                iface_address_uuids, port=endpoint.port, secure=endpoint.ssl)
                    if rsp.success == True:
                        _logger.info("Successfully added runtime endpoint at {}:{}".format(address, port))
                    else:
                        _logger.error("Failed to create endpoint:\n:{}\n{}".format(
                                                                        json.dumps(endpoint, indent=4), rsp.data))
            if aac_config.runtime_properties.users:
                old_users = optional_list(self.aac.user_registry.list_users().json)
                for user in aac_config.runtime_properties.users:
                    old_user = optional_list(filter_list("id", user.name, old_users))
                    if old_user:
                        rsp = self.aac.user_registry.delete_user(old_user['id'])
                        if rsp.success == True:
                            _logger.info("Successfully removed old user from user registry.")
                        else:
                            _logger.error("Failed to remove old user from registry, skipping create {} user.".format(
                                                                                                        user.name))
                            continue
                    rsp = self.aac.user_registry.create_user(user.name, passowrd=user.password, groups=user.groups)
                    if rsp.success == True:
                        _logger.info("Successfully added {} to the runtime user registry".format(user.name))
                    else:
                        _logger.error("Failed to create user:\n{}\n{}".format(json.dumps(user, indent=4), rsp.data))
            if aac_config.runtime_properties.groups:
                old_groups = optional_list(self.aac.user_registry.list_groups().json)
                for group in aac_config.runtime_properties.groups:
                    old_group = optional_list(filter_list("id", group.name, old_groups))
                    if old_group:
                        rsp = self.aac.user_registry.deletegroup(old_group['id'])
                        if rsp.success == True:
                            _logger.info("Successfully removed old group from user registry.")
                        else:
                            _logger.error("Failed to remove old group from registry, skipping create {} group.".format(
                                                                                                        group.name))
                            continue
                    rsp = self.aac.user_registry.create_group(group.name, users=groups.users)
                    if rsp.success == True:
                        _logger.info("Successfully added {} to the runtime user registry".format(group.name))
                    else:
                        _logger.error("Failed to create group:\n{}\n{}".format(json.dumps(user, indent=4), rsp.data))


    def configure(self):
        if self.config.access_control == None:
            _logger.info("No Access Control configuration detected, skipping")
            return
        self.runtime_configuration(self.config.access_control)
        self.upload_files(self.config.access_control)
        self.attributes_configuration(self.config.access_control)
        self.obligation_configuration(self.config.access_control)
        self.pip_configuration(self.config.access_control)
        self.push_notifications(self.config.access_control)
        self.server_connections(self.config.access_control)
        self.fido2_configuration(self.config.access_control)
        if self.needsRestart == True:
            deploy_pending_changes()

        self.risk_profiles(self.config.access_control)
        self.access_control(self.config.access_control)
        self.api_protection_configuration(self.config.access_control)
        if self.needsRestart == True:
            deploy_pending_changes()

        self.authentication_configuration(self.config.access_control)
        self.scim_configuration(self.config.access_control)
        self.mmfa_configuration(self.config.access_control)
        self.advanced_config(self.config.access_control)
        if self.needsRestart == True:
           deploy_pending_changes()
