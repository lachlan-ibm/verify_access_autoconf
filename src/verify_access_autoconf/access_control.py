#!/bin/python3

import logging
import json
import os
import typing

from .util.configure_util import config_base_dir, deploy_pending_changes
from .util.data_util import Map, FILE_LOADER

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

                TO: DO

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
        if config.push_notification_providers != None:
            existing = self.aac.push_notification.list_providers().json
            for provider in config.push_notification_providers:
                rsp = None
                verb = 'None'
                old = list(filter(lambda x: (provider.app_id != None and x['app_id'] == provider.app_id), existing))
                if old.length != 0:
                    rsp = self.aac.push_notification.update(old[0]['pnr_id'], **provider)
                    verb = 'modified' if rsp.success == True else 'modify'
                else:
                    rsp = self.aac.push_notification.create(**provider)
                    verb = 'created' if rsp.success == True else 'create'
                if rsp.success == True:
                    _logger.info("Successfully {} {} push notification provider".format(verb, provider.app_id))
                else:
                    _logger.error("Failed to {} push notification provider:\n{}\n{}".format(verb, 
                                                                json.dumps(provider, indent=4), rsp.content))
                



    def _cba_obligation(self, existing, obligation):
        obg_id = None
        for obl in existing:
            if obl["obligationURI"] == obligation.uri:
                obg_id = obl['id']
                break
        rsp = None
        if obg_id:
            rsp = self.aac.access_control.update_obligation(obg_id, name=obligation.name, 
                    description=obligation.description, obligationURI=obligation.uri, 
                    type=obligation.type, parameters=obligation.parameters, 
                    properties=obligation.properties)
            verb = "created" if rsp.success == True else "create"
        else:
            rsp = self.aac.access_control.create_obligation(name=obligation.name, 
                    description=obligation.description, obligationURI=obligation.uri, 
                    type=obligation.type, parameters=obligation.parameters, 
                    properties=obligation.properties)
            verb = "updated" if rsp.success == True else "update"
        if rsp.success == True:
            _logger.info("Successfully {} {} obligation.".format(verb, obligation.name))
        else:
            _logger.error("Failed to {} obligation:\n{}\n{}".format(verb, 
                                                        json.dumps(obligation, indent=4), rsp.content))
        return

    def _cba_attribute(self, existing, attribute):
        attr_id = None
        for attr in existing:
            if attr['name'] == attribute.name and attr['uri'] == attribute.uri:
                attr_id = attr['id']
                break
        rsp = None
        if attr_id:
            rsp = self.aac.attribute.update_attribute(attr_id, **attribute)
            verb = "updated" if rsp.success else "update"
        else:
            rsp = self.aac.attrbute.create_attribute(**attribute)
            verb = "created" if rsp.success == True else "create"
        if rsp.success == True:
            _logger.info("Successfully {} {} attribute.".foramt(verb, attribute.name))
        else:
            _logger.error("Failed to {} attribute:\n{}\n{}".format(verb, json.dumps(attribute, indent=4), rsp.content))


    def _cba_resource(self, resource):
        methodArgs = {
            "server": resource.server,
            "resourceUri": resource.uri,
            "policies": resource.policies,
            "policy_combining_algorithm": resource.policy_combining_algorithm,
            "cache": resource.cache
        }
        rsp = self.aac.access_control.configure_resource(**methodArgs)
        if rsp.success == True:
            _logger.info("Successfully configured {} resource for {}".format(resource.uri, respurce.server))
        else:
            _logger.error("Failed to create resource with configuration:\n{}\n{}".format(
                json.dumps(resource, indent=4), rsp.data))

    def _cba_policy(self, old_policies, policy):
        plc_id = None
        for p in old_policies:
            if p['name'] == policy.name:
                plc_id = p['id']
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
        if plc_id:
            rsp = self.aac.access_control.update_policy(plc_id, **methodArgs)
            verb = "updated" if rsp.success == True else "update"
        else:
            rsp = self.aac.access_control.create_policy(**methodArgs)
            verb = "created" if rsp.success == True else "create"
        if rsp.success == True:
            _logger.info("Successfully {} {} Access Control Policy".format(verb, policy.name))
        else:
            _logger.error("Failed to {} Access Control Policy with config:\n{}\n{}".format(verb
                                                                    json.dumps(policy, indent=4), rsp.data))


    class Access_Control(typing.TypedDict):
        '''
        Example::

                    TO: DO

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
            server: str
            'The web container that contains the protected object space for a server instance.'
            resource_uri: str
            'The resource URI of the resource in the protected object space.'
            policies: str
            'Array of attachments (policy, policy sets, and API protection definitions) that define the access protection for this resource.'
            policy_combining_algorithm: typing.Optional[str]
            '"permitOverrides" to allow access to the rescource if any of the attachments return permit; "denyOverrides" to deny access to the resource if any of the attachments return deny. Default is "denyOverrides".'
            cache: int
            '0 to disable the cache for this resource, -1 to cache the decision for the lifetime of the session or any number greater than 1 to set a specific timeout (in seconds) for the cached decision. If not specified a default of 0 will be used.'

        class Attribute(typing.TypedDict):
            category: str
            'The part of the XACML request that the attribute value comes from: "Subject", "Environment", "Action", "Resource".'
            matcher: str
            'ID of the attribute matcher that is used to compare the value of this attribute in an incoming device fingerprint with an existing device fingerprint of the user.'
            issuer: str
            'The name of the policy information point from which the value of the attribute is retrieved.'
            description: typing.Optional[str]
            'A description of the attribute.'
            name: str
            'A unique name for the attribute.'
            uri: str
            'The identifier of the attribute that is used in the generated XACML policy.'
            datatype: str
            'The type of values that the attribute can accept: "String", "Integer", "Double", "Boolean", "Time", "Date", "X500Name".'
            storage_session: typing.Optional[bool]
            'True if the attribute is collected in the user session.'
            storage_behavior: typing.Optional[bool]
            'True if historic data for this attribute is stored in the database and used for behavior-based attribute matching.'
            type_risk: typing.Optional[bool]
            'True if the attribute is used in risk profiles.'
            type_policy: typing.Optional[bool]
            'True if the attribute is used in policies.'


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
            parameters: typing.List[str]
            'Array of parameters associated with the obligation.'
            properties: typing.Optional[typing.List[Property]]
            'Array of properties associated with the obligations.'

        policies: typing.Optional[typing.List[Policy]]
        'List of Risk Based Access policies to create.'
        resources: typing.Optional[typing.List[Resource]]
        'List of resources to be created and corresponding policies which should be attached to each resource.'
        attributes: typing.Optional[typing.List[Attribute]]
        'List of credential attributes to use when making Risk Based Access decisions.'
        obligations: typing.Optional[typing.List[Obligation]]
        'List of policy obligations to create.'

    def access_control(self, aac_config):
        if aac_config.access_control != None:
            ac = aac_config.access_control
            if ac.resources != None:
                for resource in ac.resources:
                    self._cba_resource(resource)
            if ac.attributes != None:
                old_attributes = self.aac.attribute.list_attributes().json
                if old_attributes == None: old_attributes = []
                for attribute in ac.attributes:
                    self._cba_attribute(old_attributes, attribute)
            if ac.obligations != None:
                old_obligations = self.aac.access_control.list_obligations().json
                if old_obligations == None: old_obligations = []
                for obligation in ac.obligations:
                    self._cba_obligation(old_obligations, obligation)
            if ac.policies != None:
                old_policies = self.aac.access_control.list_policies().json
                if old_policies == None: old_policies = []
                for policy in ac.policies:
                    self._cba_policy(old_policies, policy)


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
        'The Verify Access assigend property id. Either the property ID or name must be defined.'
        name: typing.Optional[str]
        'The name of the advanced configuration property. Either the property ID or name must be defined.'
        value: str
        'The updated value of the advanced configuration property.'

    def advanced_config(self, aac_config):
        if aac_config.advanced_configuration != None:
            old_config = self.aac.advanced_configuration.list().json
            for advConf in aac_config.advanced_configuration:
                old = None; id=None; sensitive=None
                if advConfig.name:
                    old = list(filter(lambda x: x['key'] == advConf.name, old_config))
                else:
                    old = list(filter(lambda x: x['id'] == advConf.id, old_config))
                if old.length != 1:
                    _logger.error("Could not find {} in list of advanced cnfigurtion parameters".format(advConf.name))
                    continue
                else:
                    old = old[0]
                    id = old['id']
                    sensitive = old['sensitive']
                rsp = self.aac.advanced_config.update(id, value=advConf.value, sensitive=sensitive)
                if rsp.success == True:
                    _logger.info("Successfully updated advanced configuration {}".format(old['key']))
                else:
                    _logger.error("Failed to upate advanced configuration with:\n{}\n{}".format(
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

        class Schema(typing.TypedDict):

            class AttributeMode(typing.TypedDict):

                class Mode(typing.TypedDict):
                    attribute: str
                    mode: str
                    subatttribute: str

                schema: str
                'The name of the schema.'
                modes: typing.List[Mode]
                'An array of customised attribute modes for the schema.'

            class _ScimProperties(typing.TypedDict):
                '''
                Shared SCIM configuration proprty definitions.
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


            class UserSchemaProperties(_ScimProperties):
                '''
                "urn:ietf:params:scim:schemas:core:2.0:User"
                '''
                ldap_connection: str
                'The name of the ldap server connection.'
                ldap_object_classes: typing.List[LDAPObjectClass]
                'The list of ldap object classes that are used to indicate a user object.'
                search_suffix: str
                'The suffix from which searches will commence in the LDAP server.'
                user_suffix: str
                'The suffix that will house any users that are created through the SCIM interface.'
                user_dn: typing.Optional[str]
                'The LDAP attribute that will be used to construct the user DN. Defaults to 'cn'.'
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

            class EnterpriseSchemaProperties(_ScimProperties):
                '''
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
                '''
                mappings: typing.List[SCIMMapping]
                'The list of SCIM enterprise user attribute mappings.'

            class GroupSchemaProperties(_ScimProperties):
                '''
                "urn:ietf:params:scim:schemas:core:2.0:Group"
                '''
                ldap_object_classes: typing.List[LDAPObjectClass]
                'The list of ldap object classes that are used to indicate a group object.'
                group_dn: str
                'The LDAP attribute that will be used to construct the group DN.'

            class ISVAUserProperties(_ScimProperties):
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
            'Name of schema properties to modify. See `_ScimProperties` subclasses for the valid schema names.'
            properties: _ScimProperties
            'Schema unique properties to apply.'

        admin_group: str
        'The name of the administrator group. Used to determine if the authenticated user is an administrator.'
        schema: typing.Optional[Typing.List[Schema]]
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
            for schema in aac_config.scim:
                rsp = self.aac.scim_config.get_schema(schema.uri)
                if rsp.success == False:
                    _logger.error("Failed to get config for schema [{}]".format(schema.uri))
                    return
                config = {**rsp.json, **schema.properties}
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
                    logger.info("connection {} exists, deleting before recreating".format(connection.name))
                    rsp = {"ci": self.aac.server_connections.delete_ci,
                          "ldap": self.aac.server_connections.delete_ldap,
                          "isamruntime": self.aac.server_connections.delete_runtime,
                          "oracle": self.aac.server_connections.delete_jdbc,
                          "db2": self.aac.server_connections.delete_jdbc,
                          "soliddb": self.aac.server_connections.delete_jdbc,
                          "postgresql": self.aac.server_connections.delete_jdbc,
                          "smtp": self.aac.server_connections.delete_smtp,
                          "ws": self.aac.server_connections.delete_web_service}.get(connection.type, None)(c['uuid'])
                    return rsp.success
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
                      ci_tenant: !secret default/isva-secrets:ci_tenatn
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
        class _Connection(typing.TypedDict):
            name: str
            'THe name of the connection. This is required for all connection types.'
            description: typing.Optional[str]
            'A description of the connection. This is optional for all connection types.'
            type: str
            'The type of server connection. This is required for all connection types.'
            locked: typing.optional[bool]
            'Controls whether the connection is allowed to be deleted. If not present, a default of ``false`` will be assumed. This is optional for all connection types.'


        class IbmsecVerifyConnection(_Connection):
            '''
            ci
            '''
            admin_host: str
            client_id: str
            client_secret: str
            ssl: bool
            ssl_truststore: typing.Optional[str]
            ssl_key_label: typing.Optional[str]
            user_endpoint: typing.Optional[str]
            authorize_endpoint: typing.Optional[str]
            authenticatiors_endpoint: typing.Optional[str]
            authnmethods_endpoint: typing.Optional[str]
            factors_endpoint: typing.Optional[str]


        class Java_Database_Connection(_Connection):
            '''
            jdbc
            '''
            server_name: str
            port: intssl: bool
            user: str
            password: str
            type: typing.Optional[str]
            service_name: typing.Optional[str]
            database_name: typing.Optional[str]
            age_timeout: typing.Optional[int]
            connection_timeout: typing.Optional[int]
            max_connections_per_thread: typing.Optional[int]
            max_idle_time: typing.Optional[int]
            max_pool_size: typing.Optional[int]
            min_pool_size: typing.Optional[int]
            connections_per_thread: typing.Optional[int]
            connection_purge_policy: typing.Optional[str]
            connection_reap_time: typing.Optional[str]
            'Amount of time between runs of the pool maintenance thread. A value of "-1" disables pool maintenace. Default value is "3m".'


        class RedisConnection(_Connection):
            '''
            redis
            '''
            class Server(typing.TypedDict):
                hostname: str
                port: str

            deployment_model: str
            master_name: str
            hostname: str
            port: int
            user: typing.Optional[str]
            password: typing.Optional[str]
            ssl: bool
            ssl_trustsotre: typing.Optional[str]
            ssl_key_label: typing.Optional[str]
            connection_timeout: typing.Optional[int]
            idle_timeout: typing.Optional[int]
            max_pool_size: typing.Optional[int]
            min_pool_size: typing.Optional[int]
            max_idle_size: typing.Optional[int]
            io_timeout: typing.Optional[int]
            servers: typing.Optional[typing.List[Server]]

        class LDAPConnection(_Connection):
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

        class SMTPConnection(_Connection):
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

        class VerifyAccessRuntimeConnection(_Connection):
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

        class WebServiceConnection(_Connection):
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

        connections: typing.List[_Connection]
        'List of server connections to create or update. Propertes of indivudual connections are described in the `_Connection` subclasses.'


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


    class Template_Files(typing;TypedDict):
        '''
        Example::
                 template_files:
                 - aac/isva_template_files.zip
                 - login.html
                 - 2fa.html

        '''
        template_files: typing.List[str]
        'List of files or zipfiles to upload as HTML template pages. Path to files can be relative to the ``ISVA_CONFIG_BASE`` property or fully-qualified file paths.'

    def upload_template_files(self, template_files):
        for file_pointer in template_files:
            rsp = None
            if file_pointer.get("type") == "file":
                rsp = self.aac.template_files.create_file(file_pointer['directory'], file_name=file_pointer['name'],
                        contents=file_pointer['contents'])
            else:
                rsp = self.aac.template_files.create_directory(file_pointer['directory'], dir_name=file_ponter['name'])
            if rsp.success == True:
                _logger.info("Successfully created template file {}".format(file_pointer['path']))
            else:
                _logger.error("Failed to create tempalte file {}".format(file_pointer['path']))

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

        mapping_rules: typing.List[str]:
        'List of files to upload as JavaScript mapping rules. Path to files can be relative to the ``ISVA_CONFIG_BASE`` property or fully-qualified file paths.'

    def upload_mapping_rules(self, _type, maping_rules):
        for mapping_rule in mapping_rules:
            rsp = self.aac.mapping_rule.create_rule(file_name=mapping_rule["path"], rule_name=mapping_rule['name'],
                    category=_type, content=mapping_rule['contents'])
            if rsp.success == True:
                _logger.info("Successfully uploaded {} mapping rule".foramt(mapping_rule['name']))
            else:
                _logger.error("Failed to upload {} mapping rule".format(mapping_rule['name']))

    def upload_files(self, config):
        if config.template_files != None:
            for entry in config.template_files:
                parsed_files = FILE_LOADER.read_files(entry, include_directories=True)
                self.upload_template_files(parsed_files)
        if config.mapping_rules != None:
            for entry in config.mapping_rules:
                for file_pointer in entry.files:
                    parsed_files = FILE_LOADER.read_files(file_pointer)
                self.upload_mapping_rules(entry.type, parsed_files)


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
                       behaior: false
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
            behaviour: bool
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
            for attr in aac_config.attributes:
                rsp = self.aac.attributes.create_attribute(category=attr.category, matcher=attr.matcher, issuer=attr.issuer,
                        description=attr.description, name=attr.name, datatype=attr.datatype, uri=attr.uri,
                        storage_session=attr.storage.session, storage_behavior=attr.storage.behavior, 
                        storage_device=attr.storage.device, type_risk=attr.type.risk, type_policy=attr.type.policy)
                if rsp.success == True:
                    _logger.info("Successfully created attribute {}".format(attr.name))
                else:
                    _logger.error("Failed to create attribute [{}] with config:\n{}\n{}".format(
                        attr.name, json.dumps(attr, indent=4), rsp.data))


    def _configure_api_protection_definition(self, defintion):
        methodArgs = {"name": definition.name, "description": definition.description, "token_char_set": definition.access_token_char_set,
                "access_token_lifetime": definition.access_token_lifetime, "access_token_length": defintion.access_token_length, 
                "authorization_code_lifetime": definition.authorizaton_code_lifetime, "authorization_code_length": definition.authorization_code_length,
                "refresher_token_length": definition.refresh_token_length, "max_authorization_grant_lifetime": definition.max_authorization_grant_lifetime,
                "pin_length": definition.pin_length, "enforce_single_use_authorization_grant": definition.enforce_single_use_grant, 
                "issue_refresh_token": definition.issue_refresh_token, "enforce_single_access_token_per_grant": definition.single_token_per_grant, 
                "enable_multiple_refresh_tokens_for_fault_tolerance": defintion.multiple_refresh_tokens, "pin_policy_enabled": definition.pin_policy, 
                "grant_types": definition.grant_types, "attribute_sources": definition.attribute_sources
            }
        if definition.oidc:
            methodArgs.update({
                "oidc_enabled": True, "iss": definition.oidc.iss, "poc": definition.oidc.poc, "lifetime": definition.oidc.lifetime,
                "alg": definition.oidc.alg, "db": definition.oidc.db, "Cert": definition.oidc.cert
            })
            if definition.oidc.enc:
                methodArgs.update({
                    "enc_enabled": True, "enc_alg": definition.oidc.enc.alg, "enc_enc": : definition.oidc.enc.enc
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
                rsp = self.aac.api_protection.create_mapping_rule(name=definition.name + "PreTokenGeneration",
                        category="OAUTH", file_name=mapping_rule["name"], content=mapping_rule['contents'])
                if rsp.success == True:
                    _logger.info("Successfully uploaded {} Pre-Token Mapping Rule".foramt(definition.name))
                else:
                    _logger.error("Failed to upload {} Pre-Token Mapping Rule".format(defintion.name))
        if definition.post_token_mapping_rule:
            mapping_rule = FILE_LOADER.read_file(definition.post_token_mapping_rule)
            if len(mapping_rule) != 1:
                _logger.error("Can only specify one Post-Token Mapping Rule")
            else:
                mapping_rule = mapping_rule[0]
                rsp = self.aac.api_protection.import_mapping_rule(name=definition.name + "PostTokenGeneration",
                        categore="OAUTH", file_name=mapping_rule['name'], content=mapping_rule['contents'])
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
                definition=client.api_defintition, client_id=client.client_id, client_secret=client.client_secret)
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
                       poc: #TODO
                       iss: #TODO
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
                       - "http://localhost:19080/auth"
                     company_name: "JPNorvill"
                     contact_type: "TECHNICAL"
                     definition: "Verify Demo - Open Banking"

        '''

        class Definition(typing.TypedDict):

            class OIDC(typing.TypedDict):

                class OIDC_Encoding(typing.TypedDict):
                    enabled; bool
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
                'JWT encrption config.'
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
        clients: typing.Optional[typing.List[Client]]

    def api_protection_configuration(self, aac_config):
        if aac_config.api_protection != None and aac_config.api_protection.definitions != None:
            for definition in aac_config.api_protection.definitions:
                self._configure_api_protection_definition(definition)

            if aac_config.api_protection.clients != None:
                definitions = self.aac.api_protection.list_definitions()
                for client in aac_config.api_protection.clients:
                    self._configure_api_protection_client(definitions, client)


    def _configure_mechanism(self, mechTypes, existing_mechanisms, mechanism):
        try:
            typeId = list(filter(lambda _type: _type['type'] == mechanism.type, mechTypes))[0]['id']
        except (IndexError, KeyError):
            _logger.error("Mechanism [{}] specified an invalid type, skipping".format(mechanism))
            return
        props = None
        if mechanism.properties != None and isinstance(mechanism.properties, list):
            props = []
            for e in mechanism.properties: 
                props += [{"key": k, "value": v} for k, v in e.items()]
        old_mech = list(filter( lambda m: m['uri'] == mechanism.uri, existing_mechanisms))
        rsp = None
        if old_mech:
            old_mech = old_mech[0]
            rsp = self.aac.authentication.update_mechanism(id=old_mech['id'], description=mechanism.description, 
                    name=mechanism.name, uri=mechanism.uri, type_id=typeId, predefined=old_mech['predefined'], 
                    properties=props, attributes=mechanism.attributes)
        else:
            rsp = self.aac.authentication.create_mechanism(description=mechanism.description, name=mechanism.name,
                    uri=mechanism.uri, type_id=typeId,  properties=props, attributes=mechanism.attributes)
        if rsp.success == True:
            _logger.info("Successfully set configuration for {} mechanism".format(mechanism.name))
            self.needsRestart = True
        else:
            _logger.error("Failed to set configuration for {} mechanism with:\n{}\n{}".format(
                mechanism.name, json.dumps(mechanism, indent=4), rsp.data))

    def _configure_policy(self, existing_policies, policy):
        rsp = None
        old_policy = list(filter(lambda p: p['uri'] == policy.uri, existing_policies))
        if old_policy:
            old_policy = old_policy[0]
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



    class Authentication(typng.TypedDict):
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
                      - usernamePasswordAuthentication.ldapBindDN: "cn=root,secAuthority=Default"
                      - usernamePasswordAuthentication.maxServerConnections: "16"
                      - usernamePasswordAuthentication.mgmtDomain: "Default"
                      - usernamePasswordAuthentication.sslEnabled: "true"
                      - usernamePasswordAuthentication.ldapPort: "636"
                      - usernamePasswordAuthentication.sslTrustStore: "lmi_trust_store"
                      - usernamePasswordAuthentication.userSearchFilter: "usernamePasswordAuthentication.userSearchFilter"
                      - usernamePasswordAuthentication.ldapBindPwd: "Passw0rd""
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
                        reCAPTCHA.apiKey: "6LchOAgUAAAAAAqUuuyy8XLDkO8LJOq-bCLynVoj"
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

            class Atrribute(typing.TypedDict):
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


        '''


    def mmfa_configuration(self, aac_config):
        if aac_config.api_protection != None and aac_config.api_protection.clients != None:
            api_clients = self.aac.api_protection.list_clients()
            for client in api_clietns:
                if client.name == aac_config.mmfa.client_id:
                    aac_config.mmfa.client_id = client.name
                    break
        if aac_config.mmfa != None:
            rsp = self.aac.mmfaconfig.update(**aac_config.mmfa)
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

    def _upload_mediator(self, mediator):
        mediator_list = FILE_LOADER.read_files(mediator)
        for mediator_rule in mediator_list:
            rsp = self.aac.fido2_config.create_mediator(name=mediator_rule['name'], filename=mediator_rule['path'])
            if rsp.success == True:
                _logger.info("Successfully created {} FIDO2 Mediator".format(mediator_rule['name']))
            else:
                _logger.error("Failed to create {} FIDO2 Mediator".format(mediator_rule['name']))

    def _create_relying_party(self, rp):
        if rp.metadata:
            metadata_list = self.aac.fido2_config.list_metadata().json()
            for pos, metadata in enumerate(rp.metadata):
                for uploaded_metadata in metadata_list:
                    if uploaded_metadata['filename'] == metadata:
                        rp.metadata[pos] = uploaded_metadata['id']
                        break
        if rp.use_all_metadata:
            metadata_list = self.aac.fido2_config.list_metadata().json()
            for uploaded_metadata in metadata_list:
                rp.metadata += [uploaded_metadata['id']]

        if rp.mediator:
            medaitor_list = self.aac.fido2_config.list_mediator().json()
            for mediator in mediator_list:
                if mediator['fileName'] == rp.mediator:
                    rp.mediator = mediator['id']
                    break
        methodArgs = {
                "name": rp.name,
                "rp_id": rp.rp_id,
                "origins": rp.origins,
                "metadata_set": rp.metadata,
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
                        "attestation_android_safetynet_max_age": rp.attestation.android.safetynet_max_age,
                        "attestation_android_safetynet_clock_skew": rp.attestation.android.safetynet_clock_skew
                    })
        rsp = self.aac.fido2_config.create_relying_party(**methodArgs)
        if rsp.success == True:
            _logger.info("Successfully created {} FIDO2 Relying Party".format(rp.name))
        else:
            _logger.error("Failed to create {} FIDO2 Relying Party with configuration:\n{}\n{}".format(rp.name,
                json.dumps(rp, indent=4), rsp.content))

    def fido2_configuration(self, aac_config):
        if aac_config.fido2 != None:
            fido2 = aac_config.fido2
            if fido2.metadata != None:
                for metadata in fido2.metadata:
                    self._upload_metadata(metadata)
            if fido2.mediators != None:
                for mediator in fido2.mediators:
                    self._upload_mediator(mediator)
            if fido2.relying_parties != None:
                for rp in fido2.relying_parties:
                    self._create_relying_party(rp)


    def configure(self):
        if self.config.access_control == None:
            _logger.info("No Access Control configuration detected, skipping")
            return
        self.upload_files(self.config.access_control)
        self.push_notifications(self.config.access_control)
        self.server_connections(self.config.access_control)
        self.fido2_configuration(self.config.access_control)
        self.api_protection_configuration(self.config.access_control)
        if self.needsRestart == True:
            deploy_pending_changes()

        self.attributes_configuration(self.config.access_control)
        self.authentication_configuration(self.config.access_control)
        self.scim_configuration(self.config.access_control)
        self.mmfa_configuration(self.config.access_control)
        self.advanced_config(self.config.access_control)
        if self.needsRestart == True:
           deploy_pending_changes()
