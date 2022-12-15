#!/bin/python3

import logging
import json
import os

from .util.configure_util import config_base_dir, deploy_pending_changes
from .util.data_util import Map, FILE_LOADER

_logger = logging.getLogger(__name__)

class AAC_Configurator(object):

    config = Map()
    aac = None
    factory = None

    def __init__(self, config, factory):
        self.aac = factory.get_access_control()
        self.factory = factory
        self.config = config


    def push_notifications(self, config):
        #TODO
        return

    def _cba_obligation(self, obligation):
        #TODO
        return

    def _cba_attribute(self, attribute):
        #TODO
        return

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

    def _cba_policy(self, policy):
        old_policies = self.aac.access_control.list_policies().json
        exists = False
        for p in old_policies:
            if p['name'] == policy.name:
                exists = True
                break
        methodArgs = {
                "name": policy.name,
                "description": policy.description,
                "dialect": policy.dialect if policy.dialect else "urn:oasis:names:tc:xacml:2.0:policy:schema:os",
                "policy": policy.policy,
                "attributes_required": policy.attributes_required
            }
        rsp = None
        if exists == True:
            rsp = self.aac.access_control.update_policy(**methodArgs)
        else:
            rsp = self.aac.access_control.create_policy(**methodArgs)
        if rsp.success == True:
            _logger.info("Successfully created {} Access Control Policy")
        else:
            _logger.error("Failed to create Access Control Policy with config:\n{}\n{}".format(
                json.dumps(policy, indent=4), rsp.data))

    def access_control(self, aac_config):
        if aac_config.access_control != None:
            ac = aac_config.access_control
            if ac.policies != None:
                for policy in ac.policies:
                    _cba_policy(policy)
            if ac.resources != None:
                for resource in ac.resources:
                    _cba_resource(resource)
            if ac.attributes != None:
                for attribute in ac.attributes:
                    _cba_attribute(attribute)
            if ac.obligations != None:
                for obligation in ac.obligations:
                    _cba_obligation(obligation)


    def advanced_config(self, aac_config):
        if aac_config.advanced_configuration != None:
            for advConf in aac_config.advanced_configuration:
                rsp = self.aac.advanced_config.update(
                        advConf.id, value=advConf.value, sensitive=advConf.sensitive)
                if rsp.success == True:
                    _logger.info("Successfully updated advanced configuration " + str(advConf.id))
                else:
                    _logger.error("Failed to upate advanced configuration with:\n{}\n{}".format(
                        json.dumps(advConf, indent=4), rsp.data))


    def scim_configuration(self, aac_config):
        #TODO
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
                connection_ssl_auth=props.cert_file, connection_host_port=props.port, connection_ssl=props.ssl,
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
                connection_ssl_auth_key=props.cert_file, connection_ssl=props.ssl)
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
        rsp = self.aac.api_protection.create_definition(name=definition.name, description=definition.description, 
                token_char_set=definition.access_token_char_set, access_token_lifetime=definition.access_token_lifetime,
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

    def api_protection_configuration(self, aac_config):
        if aac_config.api_protection != None and aac_config.api_protection.definitions != None:
            for definition in aac_config.api_protection.definitions:
                self._configure_api_protection_definition(definition)

            if aac_config.api_protection.clients != None:
                definitions = self.aac.api_protection.list_definitions()
                for client in aac_config.api_protection.clients:
                    self._configure_api_protection_client(definitions, client)


    def _configure_mechanism(self, mechanism):
        mechTypes = self.aac.authentication.list_mechanism_types().json
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
        existing_mechanisms = self.aac.authentication.list_mechanisms().json
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
        else:
            _logger.error("Failed to set configuration for {} mechanism with:\n{}\n{}".format(
                mechanism.name, json.dumps(mechanism, indent=4), rsp.data))

    def _confiugre_policy(self, existing_policies, policy):
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
        else:
            _logger.error("Failed to set configuration for {} policy with:\n{}\n{}".format(
                policy.name, json.dumps(policy, indent=4), rsp.data))

    def authentication_configuration(self, aac_config):
        if aac_config.authentication != None:
            if aac_config.authentication.mechanisms != None:
                for mechanism in aac_config.authentication.mechanisms:
                    _configure_mechanism(mechanism)
            if aac_config.authentication.policies != None:
                existing_policies = self.aac.authentication.list_policies()
                for policy in aac_config.authentication.policies:
                    self._configure_policy(existing_policies, policy)

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
                    _upload_metadata(metadata)
            if fido2.mediators != None:
                for mediator in fido2.mediators:
                    _upload_mediator(mediator)
            if fido2.relying_parties != None:
                for rp in fido2.relying_parties:
                    _create_relying_party(rp)


    def configure(self):
        if self.config.aac == None:
            _logger.info("No Access Control configuration detected, skipping")
            return
        upload_files(self.config.aac)
        push_notifications(self.config.aac)
        server_connections(self.config.aac)
        fido2_configuration(self.config.aac)
        api_protection_configuration(self.config.aac)
        deploy_pending_changes()

        attributes_configuration(self.config.aac)
        authentication_configuration(self.config.aac)
        scim_configuration(self.config.aac)
        mmfa_configuration(self.config.aac)
        advanced_config(self.config.aac)
        deploy_pending_changes()
