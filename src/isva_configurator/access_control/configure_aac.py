#!/bin/python3

import logging
import json
import os

from .utils.constants import AAC, CONFIG_BASE_DIR, CONFIG, deploy_pending_changes

_logger = logging.getLogger(__name__)

class AAC_Configurator(object):
    def advanced_config(self, aac_config):
        if aac_config.advanced_configuration != None:
            for advConf in aac_config.advanced_configuration:
                rsp = AAC.advanced_config.update(
                        advConf.id, value=advConf.value, sensitive=advConf.sensitive)
                if rsp.success == True:
                    _logger.info("Successfully updated advanced configuration " + str(advConf.id))
                else:
                    _logger.error("Failed to upate advanced configuration with:\n{}\n{}".format(
                        json.dumps(advConf, indent=4), rsp.data))


    def scim_configuration(self, aac_config):
        if aac_config.scim != None:
            for schema in aac_config.scim:
                rsp = AAC.scim_config.get_schema(schema.uri)
                if rsp.success == False:
                    _logger.error("Failed to get config for schema [{}]".format(schema.uri))
                    return
                config = {**rsp.json, **schema.properties}
                rsp = AAC.scim_config.update_schema(schema.uri, config)
                if rsp.success == True:
                    _logger.info("Successfully updated schema [{}]".format(schema.uri))
                else:
                    _logger.error("Failed to update schema [{}] with configuration:\n{}".format(
                        schema.uri, config))


    def _ci_server_connection(self, connection):
        props = connection.properties
        rsp = AAC.server_connections.create_ci(name=connection.name, description=connection.description, locked=connection.locked,
                connection_host_name=props.hostname, connection_client_id=props.client_id, connection_client_secret=props.client_secret,
                connection_ssl_truststore=props.ssl_truststore)
        return rsp

    def _ldap_server_connection(self, connection):
        props = connection.properties
        rsp = AAC.server_connections.create_ldap(name=connection.name, description=connection.description,
                locked=connection.locked, connection_host_name=prop.hostname, connection_bind_dn=props.bind_dn,
                connection_bind_pwd=props.bind_password, connection_ssl_truststore=props.key_file,
                connection_ssl_auth=props.cert_file, connection_host_port=props.port, connection_ssl=props.ssl,
                connection_timeout=props.timeout, servers=props.servers)
        return rsp

    def _jdbc_server_connection(self, connection):
        props = connection.properties
        rsp = AAC.server_connections.create_jdbc(name=connection.name, description=connection.description,
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
        rsp = AAC.server_connections.create_smtp(name=connection.name, description=connection.description, connect_timeout=props.timeout,
                connection_host_name=props.hostname, connection_host_port=props.port, connection_ssl=props.ssl, connection_user=props.user,
                connection_password=props.password)
        return rsp

    def _ws_server_connection(self, connection):
        props = connection.properties
        rsp = AAC.server_connection.screate_web_service(name=connection.name, description=connection.description,
                locked=connection.locked, connection_url=props.url, connection_user=props.user,
                connection_password=props.password, connection_ssl_truststore=props.key_file, 
                connection_ssl_auth_key=props.cert_file, connection_ssl=props.ssl)
        return rsp

    def _remove_server_connection(self, connection):
        configured_connections = AAC.server_connections.list_all().json
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
                    rsp = {"ci": AAC.server_connections.delete_ci,
                      "ldap": AAC.server_connections.delete_ldap,
                      "isamruntime": AAC.server_connections.delete_runtime,
                      "oracle": AAC.server_connections.delete_jdbc,
                      "db2": AAC.server_connections.delete_jdbc,
                      "soliddb": AAC.server_connections.delete_jdbc,
                      "postgresql": AAC.server_connections.delete_jdbc,
                      "smtp": AAC.server_connections.delete_smtp,
                      "ws": AAC.server_connections.delete_web_service}.get(connection.type, None)(c['uuid'])
                    return rsp.success
        return True

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
                    else:
                        _logger.error("Failed to create server connection [{}] with config:\n{}".format(
                            connection.name, connection))


    def upload_template_files(self, base='.', _file=None):
        if os.path.isdir(base + '/' + _file):
            rsp = AAC.template_files.create_directory(base, isam_path)
            if rsp.success == True:
                _logger.info("Successfully created directory {}/{}".format(base, _file))
            else:
                _logger.error("Failed to create directory {}/{}".format(base, _file))
                return
            #recurse upload files
            path = base + '/' + _file
            for f in os.listdir(path):
                upload_template_files(base=path, _file=f)

        else:
            contents = open(base + '/' + _file, 'rb').read()
            rsp = AAC.template_files.create_file(base, _file, contents)
            if rsp.success == True:
                _logger.info("Successfully created template file {}/{}".format(base, _file))
            else:
                _logger.error("Failed to create tempalte file {}/{}".format(base, _file))


    def upload_mapping_rules(self, base='.', _file=None):
        path = base + '/' + _file
        if os.path.isdir(path):
            for f in os.listdir(path):
                upload_mapping_rules(base=path, _file=f)
        else:
            payload = json.load(path)
            AAC.mapping_rule.create_rule(**payload)


    def upload_files(self, config):
        cwd = os.getcwd()
        if config.template_files != None:
            for entry in config.template_files:
                os.chdir(CONFIG_BASE_DIR + '/' + entry)
                for f in os.listdir('.'):
                    upload_template_files(_file=f)

        if config.mapping_rules != None:
            for entry in config.mapping_rules:
                os.chdir(CONFIG_BASE_DIR + '/' + entry)
                for f in os.listdir('.'):
                    upload_mapping_rules(_file=f)

        os.chdir(cwd)


    def attributes_configuration(self, aac_config):
        if aac_config.attributes != None:
            for attr in aac_config.attributes:
                rsp = AAC.attributes.create_attribute(category=attr.category, matcher=attr.matcher, issuer=attr.issuer,
                        description=attr.description, name=attr.name, datatype=attr.datatype, uri=attr.uri,
                        storage_session=attr.storage.session, storage_behavior=attr.storage.behavior, 
                        storage_device=attr.storage.device, type_risk=attr.type.risk, type_policy=attr.type.policy)
                if rsp.success == True:
                    _logger.info("Successfully created attribute {}".format(attr.name))
                else:
                    _logger.error("Failed to create attribute [{}] with config:\n{}\n{}".format(
                        attr.name, json.dumps(attr, indent=4), rsp.data))


    def api_protection_configuration(self, aac_config):
        if aac_config.api_protection != None and aac_config.api_protection.definitions != None:
            for definition in aac_config.api_protection.definitions:
                rsp = AAC.api_protection.create_definition(name=definition.name, description=definition.description, 
                        token_char_set=definition.token_char_set, access_token_lifetime=definition.token_lifetime,
                        access_token_length=defintion.token_length, authorization_code_lifetime=definition.authorizaton_code_lifetime,
                        authorization_code_length=definition.authorization_code_length, refresher_token_length=definition.refresh_token_length,
                        max_authorization_grant_lifetime=definition.max_authorization_grant_lifetime, pin_length=definition.pin_length,
                        enforce_single_use_authorization_grant=definition.enforce_single_use_grant, issue_refresh_token=definition.issue_refresh_token, 
                        enforce_single_access_token_per_grant=definition.single_token_per_grant, enable_multiple_refresh_tokens_for_fault_tolerance=defintion.multiple_refresh_tokens,
                        pin_policy_enabled=definition.pin_policy, grant_types=definition.grant_types, oidc=definition.oidc)
                if rsp.success == True:
                    _logger.info("Successfully created {} API Protection definition".format(definition.name))
                else:
                    _logger.error("Failed to create {} API Protection definition with config:\n{}\n{}".format(
                        definition.name, json.dumps(definition, indent=4), rsp.data))

            if aac_config.api_protection.clients != None:
                definitions = AAC.api_protection.list_definitions()
                for client in aac_config.api_protection.clients:
                    for definition in definitions:
                        if definition['name'] == client.api_definition:
                            client.api_definition = definition['id']
                            break
                    rsp = AAC.api_protection.create_client(name=client.name, redirect_uri=client.redirect_uri,
                            company_name=client.company_name, company_url=client.company_url, contact_person=client.contact_person,
                            contact_type=client.contact_type, email=client.email, phone=client.phone, other_info=client.other_info,
                            definition=client.api_defintition, client_id=client.client_id, client_secret=client.client_secret)
                    if rsp.success == True:
                        _logger.info("Successfully created {} API Protection client.".format(client.name))
                    else:
                        _logger.error("Failed to create {} API Protection client with config:\n{}\n{}".format(
                            client.name, json.dumps(client, indent=4), rsp.data))


    def authentication_configuration(self, aac_config):
        if aac_config.authentication != None:
            if aac_config.authentication.mechanisms != None:
                mechTypes = AAC.authentication.list_mechanism_types().json
                existing_mechanisms = AAC.authentication.list_mechanisms().json
                for mechanism in aac_config.authentication.mechanisms:
                    try:
                        typeId = list(filter(lambda _type: _type['type'] == mechanism.type, mechTypes))[0]['id']
                    except (IndexError, KeyError):
                        _logger.error("Mechanism [{}] specified an invalid type, skipping".format(mechanism))
                        continue
                    rsp = None
                    props = None
                    if mechanism.properties != None and isinstance(mechanism.properties, list):
                        props = []
                        for e in mechanism.properties: 
                            props += [{"key": k, "value": v} for k, v in e.items()]
                    attrs = None
                    if mechanism.attributes != None and isinstance(mechanism.attributes, list):
                        attrs = []
                        for e in mechanism.attributes: 
                            attrs += [{"key": k, "value": v} for k, v in e.items()]
                    old_mech = list(filter( lambda m: m['uri'] == mechanism.uri, existing_mechanisms))
                    if old_mech:
                        old_mech = old_mech[0]
                        rsp = AAC.authentication.update_mechanism(id=old_mech['id'], description=mechanism.description, name=mechanism.name,
                                uri=mechanism.uri, type_id=typeId, predefined=old_mech['predefined'], properties=props, attributes=attrs)
                    else:
                        rsp = AAC.authentication.create_mechanism(description=mechanism.description, name=mechanism.name,  uri=mechanism.uri,
                                type_id=typeId,  properties=props, attributes=attrs)
                    if rsp.success == True:
                        _logger.info("Successfully set configuration for {} mechanism".format(mechanism.name))
                    else:
                        _logger.error("Failed to set configuration for {} mechanism with:\n{}\n{}".format(
                            mechanism.name, json.dumps(mechanism, indent=4), rsp.data))

            if aac_config.authentication.policies != None:
                existing_policies = AAC.authentication.list_policies()
                for policy in aac_config.authentication.policies:
                    #configure policy
                    rsp = None
                    old_policy = list(filter(lambda p: p['uri'] == policy.uri, existing_policies))
                    if old_policy:
                        old_policy = old_policy[0]
                        rsp = AAC.authentication.update_policy(old_policy['id'], name=policy.name, policy=policy.policy, uri=policy.uri,
                                description=policy.description, predefined=old_policy['predefined'], enabled=policy.enabled)
                    else:
                        rsp = AAC.authentication.create_policy(name=policy.name, policy=policy.policy, uri=policy.uri, description=policy.description,
                                enabled=policy.enabled)
                    if rsp.success == True:
                        _logger.info("Successfully set configuration for {} policy".format(policy.name))
                    else:
                        _logger.error("Failed to set configuration for {} policy with:\n{}\n{}".format(
                            policy.name, json.dumps(policy, indent=4), rsp.data))


    def mmfa_configuration(self, aac_config):
        if aac_config.mmfa != None and aac_config.api_protection != None and aac_config.api_protection.clients != None:
            api_clients = AAC.api_protection.list_clients()
            for client in api_clietns:
                if client.name == aac_config.mmfa.client_id:
                    aac_config.mmfa.client_id = client.name
                    break

            rsp = AAC.mmfaconfig.update(**aac_config.mmfa)
            if rsp.success == True:
                _logger.info("Successfully updated MMFA configuration")
            else:
                _logger.error("Failed to update MMFA configuration with:\n{}\n{}".format(
                    json.dumps(aac_config.mmfa, indent=4), rsp.data))


    def configure(self):
        config = CONFIG.aac
        if config == None:
            _logger.info("No Access Control configuration detected, skipping")
            return

        upload_files(config)
        server_connections(config)
        api_protection_configuration(config)
        deploy_pending_changes()

        attributes_configuration(config)
        authentication_configuration(config)
        scim_configuration(config)
        mmfa_configuration(config)
        advanced_config(config)
        deploy_pending_changes()
