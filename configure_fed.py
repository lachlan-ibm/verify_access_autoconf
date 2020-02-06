#!/bin/python3

import json
import os
import logging

from .constants import CONFIG, FED, deploy_pending_changes

_logger = logging.getLogger(__name__)


def configure_poc(fedration_config):
    if federation_config.points_of_contact != None:
        for poc in ederation_config.points_of_contact:
            rsp = FED.poc.create_like_credential(name=poc.name, description=poc.description,
                    authenticate_callbacks=poc.authenticate_callbacks, local_id_callbacks=poc.local_id_callbacks,
                    sign_out_callbacks=poc.sign_out_callbacks, sing_in_callbacks=poc.sign_in_callbacks,
                    authn_policy_callbacks=poc.authn_policy_callbacks)
            if rsp.success == True:
                _logger.info("Successfully configured {} Point of Contact".format(poc.name))
            else:
                _logger.error("Failed to configure {} point of contact with config:\n{}\n{}".format(
                    poc.name, json.dumps(poc, indent=4), rsp.data))


def configure_alias_service():
    return


def configure_access_policy():
    return


def _configure_saml_partner(fedId, partner):
    methodArgs = {
            "name": partner.name,
            "enabled": partner.enabled,
            "role": partner.role,
            "template_name": partner.template_name
        }
    if partner.configuration != None:
        methodArgs.update({
            "include_federation_id": config.include_federation_id,
            "logout_request_lifetime": config.logout_request_lifetime,
            "name_id_format": config.name_id_format,
            "provider_id": config.provider_id
            "artifact_resolution_service": config.artifact_resolution_service,
            "assertion_consumer_service": config.assertion_consumer_service
            })
        if config.assertion_settings != None:
            assert_settings = config.assertion_settings
            methodArgs.update({
                    "assertion_attribute_types": assert_settings.attribute_types,
                    "assertion_session_not_after": assert_settings.session_not_after,
                    "create_multiple_attribute_statements": assert_settings.create_multiple_attribute_statements
                })
        if config.encryption_settings != None:
            encryption = config.encryption_settings

    rsp = FED.federations.create_saml_partner(fedId, **methodArgs)
    if rsp.success == True:
        _logger.info("Successfully created {} SAML {} Partner".format(
            partner.name, partner.role))
    else:
        _logger.error("Failed to create {} SAML Partner with config:\n{}\n{}".format(
            partner.name, json.dumps(partner, indent=4), rsp.data))

def _configure_oidc_partner(fedId, partner):
    methodArgs = {
            "name": partner.name,
            "enabled": partner.enabled
        }
    if partner.configuration != None:
        config = partner.configuration:
        methodArgs.update({
                "client_id": config.client_id,
                "client_secret": config.client_secret,
                "metadata_endpoint": config.metadata_endpoint,
                "scope": config.scope,
                "token_endpoint_auth_method": config.token_endpoint_auth_method,
                "perform_userinfo": config.perform_userinfo,
                "signing_algoritym": config.signature_algorithm
            })
        if config.advanced_configuration != None:
            methodArgs.update({
                    "advanced_configuration_active_delegate": config.advanced_configuration.active_delegate_id,
                    "advanced_configuration_rule_id": config.advanced_configuration..mapping_rule
                })

    rsp = FED.federations.create_oidc_rp_partner(fedId, **methodArgs)
    if rsp.success == True:
        _logger.info("Successfully created {} OIDC RP Partner for Federation {}".format(
            partner.name, fedId))
    else:
        _logger.error("Failed to create {} OIDC RP Partner with config:\n{}/n{}".format(
            partner.name, json.dumps(partner, indnet=4), rsp.data))

def _configure_federation_partner(federation, partner):
    federationId = None
    _federations = FED.federations.list_federations().json
    for _federation in _federations:
        if _federation.get("name", None) == federation.name:
            federationId = _federation['id']
    method = {"ip": _configure_saml_partner,
              "sp": _configure_saml_partner,
              "rp": _configure_oidc_partner
            }.get(partner.role, None)
    if method == None:
        _logger.error("Federation partner {} does not specify a valid configuration: {}\n\tskipping . . .".format(
            partner.name, json.dumps(partner, indent=4))
    else:
        method(federationId, partner)

def _configure_saml_federation(federation):
    methodArgs = {
                "name": federation.name,
                "role": federation.role,
                "template_name": federation.template_name,
            }
    if federation.configuration != None:
        config = federation.configuration
        methodArgs.update({
                "artifact_lifetime": config.artifact_lifetime,
                "company_name": config.company_name,
                "message_valid_time": config.message_valid_time,
                "message_issuer_format": config.message_issuer_format,
                "message_issuer_name_qualifier": config.message_issuer_name_qualifier
                "point_of_contact_url": config.point_of_contact_url,
                "session_timeout": config.session_timeout
                "assertion_consumer_service": config.assertion_consumer_service,
                "name_id_format": config.name_id_format
            })
        if config.identity_mapping != None:
            methodArgs.update({
                    "identity_mapping_delegate_id": config.identity_mapping.active_delegate_id,
                    "identity_mapping_rule_reference": config.identity_mapping.mapping_rule
                })
        if config.extension_mapping != None:
            methodArgs.update({
                    "extension_mapping_delegate_id": config.extension_mapping.active_delegate_id,
                    "extension_mapping_rule_reference": config.extension_mapping.mapping_rule
                })
        if config.signature_settings != None:
            sigSetting = config.signature_settings
            methodArgs.upate({
                    "include_inclusive_namespaces": sigSetting.include_inclusive_namespaces,
                    "validate_assertion": sigSetting.validate_assertion
                })
            if sigSettings.key_info_elements != None:
                methodArgs.update({
                        "include_x509_certificate_data": sigSettings.key_info_elements.include_x509_certificate_data,
                        "include_x509_subject_name": sigSettings.key_info_elements.include_x509_subject_name,
                        "include_x509_subject_key_identifier": sigSettings.key_info_elements.include_x509_subject_key_identifier,
                        "include_x509_issuer_detials": sigSettings.key_info_elements.include_x509_issuer_detials,
                        "include_public_key": sigSettings.key_info_elements.include_public_key
                    })
            if sigSettings.signing_key_identifier != None:
                methodArgs.update({
                        "signing_keystore": sigSettings.signing_key_identifier.keystore,
                        "signing_cert": sigSettings.signing_key_identifier.certificate
                    })
            if sigSettings.signing_options != None:
                methodArgs.update({
                        "sign_authn_request": sigSettings.signing_options.sign_authn_request,
                        "sign_artifact_request": sigSettings.signing_options.sign_artifact_request,
                        "sign_artifact_response": sigSettings.signing_options.sign_artifact_response
                    })
        
    rsp = FED.federations.create_saml_federation(**methodArgs)
    if rsp.success == True:
        _logger.info("Successfully created {} SAML2.0 Federation".format(federation.name)
    else:
        _logger.error("Failed to create {} SAML2.0 Federation with config:\n{}\n{}".format(
            federation.name, json.dumps(federation, indent=4), rsp.data))
        return
    if federation.partners != None:
        for partner in federation.partners:
            _create_partner(federation, partner)


def _configure_oidc_fedation(federation):
    methodArgs = {
            "name": federation.name,
            "role": federation.role,
            "template": federation.template
        }
    if federation.configuration != None:
        config = federation.configuration
        methodArgs.update({
                "redirect_uri_prefix": config.redirect_uri_prefix,
                "response_type": config.response_types,
                "attribute_mapping": config.attribute_mapping
            })
        if config.identity_mapping != None:
            methodArgs.update({
                    "identity_mapping_delegate_id": config.identity_mapping.active_delegate_id,
                    "identity_mapping_rule": config.identity_mapping.rule
                })
        if config.advance_configuration != None:
            methodArgs.update({
                    "advance_configuration_delegate_id": config.advance_configuration.active_delegate_id,
                    "advanced_configuration_mapping_rule": config.advance_configuration.rule
                })
    rsp = FED.federations.create_oidc_rp_federation(**methodArgs)
    if rsp.success == True:
        _logger.info("Successfully created {} OIDC RP Federation".format(federation.name))
    else:
        _logger.error("Failed to create {} OIDC RP Federation with config:\n{}\n{}".format(
                federation.name, json.dumps(federation, indent=4), rsp.data))
        if federation.partners != None:
            for partner in federation.partners:
                _create_partner(federation, partner)

def configure_federations(federations):
    for federation in federations:
        method = {"SAML2_0": _configure_saml_federation,
                  "OIDC10": _configure_oidc_fedation
                  }.get(federation.protocol, None)
        if method == None:
            _logger.error("Federation {} does not specify a valid configuration: {}\n\tskipping . . .".format(
                federation.name, json.dumps(federation, indent=4)))
            continue
        else:
            method(federation)


def configure():
    config = CONFIG.federation
    configure_poc()
    configur_alias_service()
    configure_access_policy()
    configure_federations()

if __name__ == "__main__":
    configure()
