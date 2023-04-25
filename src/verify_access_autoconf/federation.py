#!/bin/python3
"""
@copyright: IBM
"""

import json
import os
import logging
import typing

from .util.configure_util import deploy_pending_changes
from .util.data_util import Map, FILE_LOADER, optional_list, filter_list, to_camel_case

_logger = logging.getLogger(__name__)

class Federation_Common(typing.TypedDict):
    '''
    Data structures which are shared between the different types of Federation protocols/roles.
    '''
    class Basic_Configuration(typing.TypedDict):
        active_delegate_id: str
        'The active module instance. Valid values are "noMetadata" and "metadataEndpointUrl".'
        metadata_endpoint_url: typing.Optional[str]
        'The /metadata endpoint URL of the provider. Only valid if ``active_delegate_id`` is "metadataEndpointUrl".'
        issuer_identifier: typing.Optional[str]
        'The issuer ("iss") value of the provider. Only valid if ``active_delegate_id`` is "noMetadata".'
        response_types: typing.Optional[typing.List[str]]
        'List of response type which determines which flow to be executed. Valid values to be included are "code", "token", "id_token". Only valid if ``active_delegate_id`` is "noMetadata".'
        authorization_endpoint_url: typing.Optional[str]
        'The /authorize endpoint URL of the provider. Only valid if ``active_delegate_id`` is "noMetadata".'
        token_endpoint_url: typing.Optional[str]
        'The /token endpoint URL of the provider. Required if "code" response type is selected. Only valid if ``active_delegate_id`` is "noMetadata".'
        user_info_endpoint_url: typing.Optional[str]
        'The /userinfo endpoint URL of the provider. Only valid if ``active_delegate_id`` is "noMetadata".'

    class Key_Identifier(typing.TypedDict):
        store: str
        'The certificate database name.'
        label: str
        'The certificate or key label.'

    class Advanced_Configuration(typing.TypedDict):
        active_delegate_id: str
        'The active module instance. Valid values are "skip-advance-map" and "default-map".'
        mapping_rule: str
        'A reference to an ID or name of an advance configuration mapping rule.'
        rule_type: str
        'The type of the mapping rule. The only supported type currently is "JAVASCRIPT".'

    class Assertion_Settings(typing.TypedDict):
        attribute_types: typing.Optional[typing.List[str]]
        'A setting that specifies the types of attributes to include in the assertion. An asterisk (*) indicates that all of the attribute types that are specified in the identity mapping file or by the custom mapping module will be included in the assertion. The default value is ["*"]. This configuration is applicable to an identity provider federation partner.'
        session_not_on_or_after: typing.Optional[int]
        'The number of seconds that the security context established for the principal should be discarded by the service provider. The default value is 3600. This configuration is applicable to an identity provider federation partner.'
        create_multiple_attribute_statements: typing.Optional[bool]
        'A setting that specifies whether to keep multiple attribute statements in the groups in which they were received. This option might be necessary if your custom identity mapping rules are written to operate on one or more specific groups of attribute statements.'
        valid_before: typing.Optional[int]
        'The number of seconds before the issue date that an assertion is considered valid. This configuration is applicable to an identity provider federation. The default value is 60.'
        valid_after: typing.Optional[int]
        'The number of seconds the assertion is valid after being issued. This configuration is applicable to an identity provider federation. The default value is 60.'

    class Assertion_Consumer_Service(typing.TypedDict):
        binding: str
        'A setting that specifies the communication method used to transport the SAML messages. The valid values are "artifact", "post", and "redirect".'
        default: bool
        'A setting that specifies whether it is the default endpoint.'
        index: int
        'A reference to a particular endpoint.'
        url: str
        'The URL of the endpoint.'

    class Artifact_Resolution_Service(typing.TypedDict):
        binding: str
        'A setting that specifies the communication method used to transport the SAML messages. The valid value is "soap".'
        default: typing.Optional[bool]
        'A setting that specifies whether it is the default endpoint.  If not provided, the default value is ``false``.'
        index: typing.Optional[int]
        'A reference to a particular endpoint. The default value is 0.'
        url: typing.Optional[str]
        'The URL of the endpoint. If not provided, the value is automatically generated from the point of contact URL.'

    class Attribute_Mapping(typing.TypedDict):
        name: str
        'Name of the source.'
        source: str
        'Attribute Source ID. '

    class Encryption_Settings(typing.TypedDict):

        block_algorithm: typing.Optional[str]
        'Block encryption algorithm used to encrypt and decrypt SAML message. Valid values are "AES-128", "AES-192", "AES-256", and "TRIPLEDES". If not provided, the default value is "AES-128".'
        key_transport_algorithm: typing.Optional[str]
        'Key transport algorithm used to encrypt and decrypt keys. Valid values are "RSA-v1.5" and "RSA-OAEP". If not provided, the default value is "RSA-OAEP". If the supplied encryptionKeyIdentifier corresponds to a network HSM device, the "RSA-OAEP" key transport is not allowed.'
        key_identifier: typing.Optional[Key_Identifier]
        'The certificate for encryption of outgoing SAML messages. If not provided, the default value is null.'
        options: typing.Optional[Encryption_Options]
        'The encryption options.'
        decryption_key_identifier: typing.Optional[Key_Identifier]
        'A public/private key pair that the federation partners can use to encrypt certain message content. The default value is null.'
        key_store: str
        'The certificate database name.'
        key_alias: str
        'The certificate or key label.'
        encrypt_name_id: bool
        'A setting that specifies whether the name identifiers should be encrypted.'
        encrypt_assertion: bool
        'A setting that specifies whether to encrypt assertions.'
        encrypt_assertion_attributes: bool
        'A setting that specifies whether to encrypt assertion attributes.'


    class Identity_Mapping(typing.TypedDict):
        class Default_Mapping_Properties(typing.TypedDict):
            rule_type: str
            'The type of the mapping rule. The only supported type currently is "JAVASCRIPT".'
            mapping_rule: str
            'A reference to an ID or name of a mapping rule.'
        
        class Custom_Mapping_Properties(typing.TypedDict):
            applies_to: str
            'Refers to STS chain that consumes call-out response. Required if "WSTRUST" ``message_format`` is specified, invalid otherwise.'
            auth_type: str
            'Authentication method used when contacting external service. Supported values are "NONE", "BASIC" or "CERTIFICATE"'
            basic_auth_username: typing.Optional[str]
            'Username for authentication to external service. Required if "BASIC" ``auth_type`` is specified, invalid otherwise.'
            basic_auth_password: typing.Optional[str]
            'Password for authentication to external service. Required if "BASIC" ``auth_type`` is specified, invalid otherwise.'
            client_key_store: typing.Optional[str]
            'Contains key for HTTPS client authentication. Required if "CERTIFICATE" ``auth_type`` is specified, invalid otherwise.'
            client_key_alias: typing.Optional[str]
            'Alias of the key for HTTPS client authentication. Required if "CERTIFICATE" ``auth_type`` is specified, invalid otherwise.'
            issuer_uri: typing.Optional[str]
            'Refers to STS chain that provides input for call-out request. Required if "WSTRUST" ``message_format`` is specified, invalid otherwise.'
            message_format: str
            'Message format of call-out request. Supported values are "XML" or "WSTRUST".'
            ssl_key_store: str
            'SSL certificate trust store to use when validating SSL certificate of external service.'
            uri: str
            'Address of destination server to call out to.'

        active_delegate_id: str
        'The active mapping module instance. Valid values are "skip-identity-map", "default-map" and "default-http-custom-map".'
        properties: typing.Union[Default_Mapping_Properties, Custom_Mapping_Properties]
        'The mapping module specific properties.'

    class Extension_Mapping(typing.TypedDict):
        active_delegate_id: str
        'The active mapping module instance. Valid values are "skip-extension-map" and "default-map". If this is a partner the value "federation-config" is also valid.'
        mapping_rule: str
        'A reference to an ID or name of an extension mapping rule.'

    class Authn_Req_Mapping(typing.TypedDict):
        active_delegate_id: str
        'The active mapping module instance. Valid values are "skip-authn-request-map" and "default-map". If this is a partner the value "federation-config" is also valid.'
        mapping_rule: str
        'A reference to an ID or name of an authentication request mapping rule.'

    class Service_Data(typing.TypedDict):
        binding: str
        'A setting that specifies the communication method used to transport the SAML messages. The valid values are "artifact", "post", "redirect" and "soap".'
        url: typing.Optional[str]
        'The URL of the endpoint. Except for "soap" binding, the value is automatically generated from the point of contact URL and will not be updated by POST or PUT operation. For "soap" binding, if not provided, the value is automatically generated from the point of contact URL.'

    class Name_Id_Format(typing.TypedDict):
        default: typing.Optional[str]
        'The name identifier format to use when the format attribute is not set, or is set to "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified". If provided, it takes precedence over the value that is configured for this partner\'s federation. If not provided, the value that is configured for this partner\'s federation is used.'
        supported: typing.Optional[typing.List[str]]
        'The list of supported name identifier formats. The default value is ["urn:oasis:names:tc:SAML:2.0:nameid-format:persistent","urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress","urn:oasis:names:tc:SAML:2.0:nameid-format:transient","urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"].'

    class Signature_Settings(typing.TypedDict):
        class Key_Identifier(typing.TypedDict):
            store: str
            'The certificate database name.'
            label: str
            'The certificate or key label.'

        class Signing_Options(typing.TypedDict):
            sign_assertion: typing.Optional[bool]
            'A setting that specifies whether to sign the assertion. The default value is ``false``.'
            sign_authn_response: typing.Optional[bool]
            'A setting that specifies whether to sign the authentication responses. The default value is ``false``.'
            sign_artifact_request: typing.Optional[bool]
            'A setting that specifies whether to sign the artifact request. The default value is ``false``.'
            sign_artifact_response: typing.Optional[bool]
            'A setting that specifies whether to sign the artifact response. The default value is ``false``.'
            sign_logout_request: typing.Optional[bool]
            'A setting that specifies whether to sign the authentication responses. The default value is ``false``.'
            sign_logout_response: typing.Optional[bool]
            'A setting that specifies whether to sign the logout response. The default value is ``false``.'
            sign_name_id_management_request: typing.Optional[bool]
            'A setting that specifies whether to sign the name ID management request. The default value is ``false``.'
            sign_name_id_management_response: typing.Optional[bool]
            'A setting that specifies whether to sign the name ID management response. The default value is ``false``.'

        class Validation_Options(typing.TypedDict):
            validate_authn_request: typing.Optional[bool]
            'A setting that specifies whether to validate the digital signature of an authentication request. The default value is ``false``.'
            validate_assertion: typing.Optional[bool]
            'A setting that specifies whether to validate the digital signature of an assertion. The default value is ``false``.'
            validate_artifact_request: typing.Optional[bool]
            'A setting that specifies whether to validate the digital signature of an artifact request.'
            validate_artifact_response: typing.Optional[bool]
            'A setting that specifies whether to validate the digital signature of an artifact response.'
            validate_logout_request: typing.Optional[bool]
            'A setting that specifies whether to validate the digital signature of a logout request.'
            validate_logout_response: typing.Optional[bool]
            'A setting that specifies whether to validate the digital signature of a logout response.'
            validate_name_id_management_request: typing.Optional[bool]
            'A setting that specifies whether to validate the digital signature of a name ID management request.'
            validate_name_id_management_response: typing.Optional[bool]
            'A setting that specifies whether to validate the digital signature of a name ID management response. '

        class Key_Info_Elements(typing.TypedDict):
            include_public_key: typing.Optional[bool]
            'A setting that specifies whether to include the public key in the KeyInfo element in the digital signature when signing a SAML message or assertion. The default value is ``false``.'
            include_x509_certificate_data: typing.Optional[bool]
            'A setting that specifies whether to include the base 64 encoded certificate data to be included in the KeyInfo element in the digital signature when signing a SAML message or assertion. The default value is ``true``.'
            include_x509_issuer_details: typing.Optional[bool]
            'A setting that specifies whether to include the issuer name and the certificate serial number in the KeyInfo element in the digital signature when signing a SAML message or assertion. The default value is ``false``.'
            include_x509_subject_key_identifier: typing.Optional[bool]
            'A setting that specifies whether to include the X.509 subject key identifier in the KeyInfo element in the digital signature when signing a SAML message or assertion. The default value is ``false``.'
            include_x509_subject_name: typing.Optional[bool]
            'A setting that specifies whether to include the subject name in the KeyInfo element in the digital signature when signing a SAML message or assertion. The default value is ``false``.'

        signature_algorithm: str
        'The signature algorithm to sign and validate SAML messages and assertions. Valid values are "RSA-SHA1", "RSA-SHA256", and "RSA-SHA512". If not provided, the default value is "RSA-SHA256".'
        digest_algorithm: str
        'The hash algorithm to apply to the transformed resources and validate its integrity. Valid values are "SHA1", "SHA256" and "SHA512". If not provided, the default value matches the configured signature algorithm - "SHA1" for "RSA-SHA1", "SHA256" for "RSA-SHA256", and "SHA512" for "RSA-SHA512".'
        signing_options: typing.Optional[Signing_Options]
        'The signing options.'
        validation_options: typing.Optional[Validation_Options]
        'The validation options.'
        include_inclusive_namespaces: typing.Optional[bool]
        'A setting that specifies whether to include the InclusiveNamespaces element in the digital signature. If provided, it takes precedence over the value that is configured for this partner\'s federation. If not provided, the value that is configured for this partner\'s federation is used.'
        key_info_elements: typing.Optional[Key_Info_Elements]
        'The KeyInfo elements to include in the digital signature.'
        signing_key_identifier: typing.Optional[Key_Identifier]
        'A public/private key pair for signing the SAML messages and the assertion. If not provided, the default value is null.'
        validation_key_identifier: typing.Optional[Key_Identifier]
        'The certificate to use to validate the signatures on the incoming SAML assertions and messages. The default value is null.'

    class Single_Sign_On_Service(typing.TypedDict):
        binding: str
        'A setting that specifies the communication method used to transport the SAML messages. The valid values are "artifact", "post" and "redirect".'
        url: str
        'The URL of the endpoint.'

    class Alias_Service_Settings(typing.TypedDict):
        db_type: str
        'A setting that specifies whether the user\'s alias is store in jdbc or ldap.'
        ldap_connection: str
        'A setting that specifies the LDAP Connection to store the alias.'
        ldap_base_dn: str
        'A setting that specifies the LDAP BaseDN to search for the user.'

    class SOAP_Settings(typing.TypedDict):
        class Server_Certificate_Validation(typing.TypedDict):
            store: str
            'The certificate database name.'
            label: typing.Optional[str]
            'The certificate label. If not provided, all certificates in the specified certificate database will be trusted. '

        class Client_Auth_Data(typing.TypedDict):
            method: str
            'The authentication method. To enable the basic authentication method, enter "ba". To enable the client certificate authentication, enter "cert". To disable client authentication, enter "none".'
            basic_auth_username: typing.Optional[str]
            'The basic authentication username.'
            basic_auth_password: typing.Optional[str]
            'The basic authentication password.'
            client_key_store: typing.Optional[str]
            'The certificate database name.'
            client_key_alias: typing.Optional[str]
            'The personal certificate label.'
    
        server_cert_validation: Server_Certificate_Validation
        'The server certificate validation data.'
        client_auth_data: Client_Auth_Data
        'The client authentication data.'

############################################################################################################
############################################################################################################
######################### Configurator #####################################################################
############################################################################################################
############################################################################################################

class FED_Configurator(object):

    factory = None
    fed = None
    config = Map()


    def __init__(self, config, factory): 
        self.fed = factory.get_federation()
        self.factory = factory
        self.config = config


    class Point_Of_Contact_Profiles(typing.TypedDict):
        '''
        Example::

                point_of_contact_profiles:
                - name: "MyPoCProfile"
                  description: "MyPoCProfile description"
                  authenticate_callbacks:
                  - index: 0
                    module_reference_id: "websealPocAuthenticateCallback"
                    parameters:
                    - name: "authentication.level"
                      value: "1"
                  sign_in_callbacks:
                  - index": 0
                    module_reference_id: "websealPocSignInCallback"
                    parameters:
                    - name: "fim.user.response.header.name"
	                  value: "am-fim-eai-user-id"
                  local_id_callbacks:
                  - index: 0
                    module_reference_id: "websealPocLocalIdentityCallback"
                    parameters:
                    - name: "fim.cred.request.header.name"
                      value: "iv-creds"
                  sign_out_callbacks:
                  - index: 0
                    module_reference_id: "websealPocSignOutCallback"
                    parameters:
                    - name: "fim.user.session.id.request.header.name"
	                  value: "user_session_id"
                  authn_policy_callbacks:
                  - index: 0
                    module_reference_id: "genericPocAuthnPolicyCallback"
                    parameters:
                    - name: "authentication.level"
                      value: "1"

        '''
        class Point_Of_Contact_Profile(typing.TypedDict):

            class Point_Of_Contact_Callback(typing.TypedDict):

                class Point_Of_Contact_Parameter(typing.TypedDict):
                    name:  str
                    'The name of the parameter.'
                    value: str
                    'The value of the parameter.'

                index: int
                'A number reflects the position in the callbacks array.'
                module_reference_id: str
                'The module ID referenced in the callback. It must be one of the supported module IDs.'
                parameters: typing.Optional[typing.List[Point_Of_Contact_Parameter]]
                'The parameters used by the callback.'

            name: str
            'A meaningful name to identify this point of contact profile.'
            description: typing.Optional[str]
            'A description of the point of contact profile.'
            authenticate_callbacks: typing.Optional[typing.List[Point_Of_Contact_Callback]]
            'An array of callbacks for authentication.'
            sign_in_callbacks: typing.Optional[typing.List[Point_Of_Contact_Callback]]
            'An array of callbacks for sign in.'
            local_id_callbacks: typing.Optional[typing.List[Point_Of_Contact_Callback]]
            'An array of callbacks for local identity.'
            sign_out_callbacks: typing.Optional[typing.List[Point_Of_Contact_Callback]]
            'An array of callbacks for sign out.'
            authn_policy_callbacks: typing.Optional[typing.List[Point_Of_Contact_Callback]]
            'An array of callbacks for authentication policy.'

        point_of_contact_profiles: typing.List[Point_Of_Contact_Profile]
        'List of point of contact profiles to configure'
        active_profile: str
        'The name of the Point of Contact profile which should be the active profile. Only one profile can be active at a time.'

    def configure_poc(self, federation_config):
        if federation_config.point_of_contact_profiles != None:
            old_pocs = optional_list(self.fed.poc.list_profiles().json)
            for poc in federation_config.point_of_contact_profiles:
                old_poc = optional_list(filter_list('name', poc.name, old_pocs))[0]
                methodArgs = copy.deepcopy(poc)
                #Convert keys from snake to camel case
                for prop in ["sign_in_callbacks", "local_id_callbacks", "sign_out_callbacks", "authn_policy_callbacks"]:
                    if prop in methodArgs:
                        methodArgs[to_camel_case(prop)] = remap_dict(methodArgs.pop(prop), {"module_reference_id", "moduleReferenceId"})

                rsp = None; verb = None
                if old_poc:
                    rsp = self.fed.poc.update_profile(old_poc['id'], **methodArgs)
                    verb = "updated" if rsp.success == True else "update"
                else:
                    rsp = self.fed.poc.create_profile(**methodArgs)
                    verb = "created" if rsp.success == True else "create"
                if rsp.success == True:
                    _logger.info("Successfully {} {} Point of Contact".format(verb, poc.name))
                else:
                    _logger.error("Failed to {} {} point of contact with config:\n{}\n{}".format(
                                            verb, poc.name, json.dumps(poc, indent=4), rsp.content))

            if "active_profile" in federation_config.point_of_contact_profiles:
                poc_profiles = self.fed.poc.list_profiles().json
                if poc_profiles:
                    profile_to_activate = optional_list(filter_list(
                            'name', federation_config.point_of_contact_profiles.active_profile, poc_profiles))[0]
                    if profile_to_activate:
                        rsp = self.fed.poc.set_current_profile(profile_to_activate['id'])
                        if rsp.success == True:
                            _logger.info("Successfully updated the active POC profile to {}".format(
                                                            federation_config.point_of_contact_profiles.active_profile))
                        else:
                            _logger.error("Failed to update the active POC profile to {}".format(
                                                            federation_config.point_of_contact_profiles.active_profile))
                    else:
                        _logger.error("Could not find the {} POC profile to activate.".format(
                                                            federation_config.point_of_contact_profiles.active_profile))


    class Security_Token_Service(typing.TypedDict):
        '''
        Example::

                sts:
                  chains:
                  - id: "appliance-post-token-map-module"
                    name: "OAuth20 Appliance Post Token Map Module"
                    description: "appliance-post-token-map-module"
                    moduleId: "OAuth20AppliancePostTokenMapModule"
                    configuration :
                    - name: "example_config_name_1"
                        value: "example_config_value_1"
                    supportedModes:
                    - "map"
                  chain_templates:
                  - name:	"STS Chain Template name"
		            description: "STS Chain Template description"
		            chain_items: 
                    - id: "default-map"
				      mode: "map"
				      prefix: "uuid3dbf4c6a-013d-15d5-bb8b-c2665e02a402"
				    - id: "default-dynamic_chain"
				      mode": verify"
				      prefix: "uuid3dbf4c6c-013d-1c48-85c8-c2665e02a402"

        '''
        class Chain_Template(typing.TypedDict):
            class Item(typing.TypedDict):
                id: str
                'The token id of an STS module.'
                mode: str
                'The mode the STS module is used in in the chain. Must be one of the supported modes of the STS module.'
                prefix: str
                'The prefix for the chain item.'

            name: str
            'A friendly name for the STS Chain Template.'
            description: str
            'A description of the STS Chain Template.'
            modules: typing.List[Item]
            'An array of the modules that make up the STS Chain Template.'
        
        class Chain(typing.TypedDict):
            class Key_Identifier(typing.TypedDict):
                key_store: str
                'The keystore name for the key.'
                key_alias: str
                'The label of the key.'
                include_certificate_data: typing.Optional[bool]
                'Whether to include the BASE64 encoded certificate data with your signature.'
                include_public_key: typing.Optional[bool]
                'Whether to include the public key with the signature.'
                include_subject_key_identifier: typing.Optional[bool]
                'Whether to include the X.509 subject key identifier with the signature.'
                include_issuer_details: typing.Optional[bool]
                'Whether to include the issuer name and the certificate serial number with the signature.'
                include_subject_name: typing.Optional[bool]
                'Whether to include the subject name with the signature.'

            class Name_Address(typing.TypedDict):
                address: str
                'The URI of the company or enterprise.'
                port_type_namespace: typing.Optional[str]
                'The namespace URI part of a qualified name for a Web service port type.'
                port_type_name: typing.Optional[str]
                'The local part of a qualified name for a Web service port type.'
                service_namespace: typing.Optional[str]
                'The namespace URI part of a qualified name for a Web service.'
                service_name: typing.Optional[str]
                'The local part of a qualified name for a Web service.'

            class Properties(typing.TypedDict):
                class Item(typing.TypedDict):
                    name: str
                    'The name of the configuration property.'
                    value: typing.List[str]
                    'The values of the configuration property.'

                partner: typing.Optional[typing.List[Item]]
                'The partner properties for all modules within the STS Chain Template referenced in the STS Chain'
                myself: typing.Optional[typing.List[Item]]
                'The self properties for all modules within the STS Chain Template referenced in the STS Chain '

            name: str
            'A friendly name for the STS Chain.'
            description: str
            'A description of the STS Chain.'
            chain_id: str
            'The Id of the STS Chain Template that is referenced by this STS Chain.'
            request_type: str
            'The type of request to associate with this chain. The request is one of the types that are supported by the WS-Trust specification.'
            token_type: typing.Optional[str]
            'The STS module type to map a request message to an STS Chain Template.'
            xpath: typing.Optional[str]
            'The custom lookup rule in XML Path Language to map a request message to an STS Chain Template.'
            sign_responses: typing.Optional[bool]
            'Whether to sign the Trust Server SOAP response messages.'
            signature_key: typing.Optional[Key_Identifier]
            'The key to sign the Trust Server SOAP response messages.'
            validate_requests: typing.Optional[bool]
            'Whether requires a signature on the received SOAP request message that contains the RequestSecurityToken message.'
            validation_key: typing.Optional[Key_Identifier]
            'The key to validate the received SOAP request message.'
            send_validation_confirmation: typing.Optional[bool]
            'Whether to send signature validation confirmation.'
            issuer: typing.Optional[Name_Address]
            'The issuer of the token.'
            applies_to: typing.Optional[Name_Address]
            'The scope of the token.'
            properties: typing.Optional[Properties]
            'The properties for all modules within the STS Chain Template referenced in the STS Chain.'

        chain_templates: typing.Optional[typing.List[Chain_Template]]
        'List of STS chain templates to create or update.'
        chains: typing.Optional[typing.List[Chain]]
        'List of STS chains to create or update.'

    def _remap_sts_chain_keys(self, chain):
            remap = {"issuer": "issuer_",
                     "validation_key": "validation_",
                     "signature": "sign_",
                     "applies_to": "applies_to_"
            }
            if "properties" in chain:
                chain["self_properties"] = chain['properties'].get("myself", [])
                chain["partner_properties"] = chain['properties'].get("partner", [])
                del chain['properties']
            temp = {}
            for key, new_key_prefix in remap.items():
                if key in chain and isinstance(chain.get(key), dict):
                    for old_key, value in chain.pop(key).items():
                        temp[new_key_prefix + old_key] = value
            chain.update(temp)
            remap = {"sign_include_certificate_data": "sign_include_cert",
                     "sign_include_public_key": "sign_include_pubkey",
                     "sign_include_subject_key_identifier": "sign_include_ski",
                     "sign_include_issuer_details": "sign_include_issuer",
                     "sign_include_subject_name": "sign_include_subject",
                     "validation_include_certificate_data": "validation_include_cert",
                     "validation_include_public_key": "validation_include_pubkey",
                     "validation_include_subject_key_identifier": "validation_include_ski",
                     "validation_include_issuer_details": "validation_include_issuer",
                     "validation_include_subject_name": "validation_include_subject"
                }
            remap_keys(chain, remap)


    def configure_sts(self, federation_config):
        if federation_config.sts != None:
            sts = federation_config.sts
            if sts.chain_templates:
                old_templates = optional_list(fed.sts.list_templates().json)
                for template in sts.chain_templates:
                    existing = optional_list(filter_list('name', template.name, old_templates))[0]
                    rsp = None; verb = None
                    if existing:
                        rsp = self.fed.sts.update_template(existing['id'], **template)
                        verb = "updated" if rsp.success == True else "update"
                    else:
                        rsp = self.fed.sts.create_template(**template)
                        verb = "created" if rsp.success == True else "create"
                    if rsp.success == True:
                        _logger.info("Successfully {} {} STS chain template.".format(verb, template.name))
                    else:
                        _logger.error("Failed to {} STS chain template:\n{}\n{}".format(verb, json.dumps(
                                                                                            template, indent=4), rsp.content))

            if sts.chains:
                old_chains = optional_list(fed.sts.list_chains().json)
                for chain in sts.chains:
                    existing = optional_list(filter_list('name', chain.name, old_chains))[0]
                    rsp = None
                    verb = None
                    methodArgs = copy.deepcopy(chain)
                    self._remap_sts_chain_keys(methodArgs)
                    if existing:
                        rsp = self.fed.sts.update_chain(existing['id'], **chain)
                        verb = "updated" if rsp.success else "update"
                    else:
                        rsp = self.fed.sts.create_chain(**chain)
                        verb = "created" if rsp.success == True else "create"
                    if rsp.success == True:
                        _logger.info("Successfully {} {} STS chain.".format(verb, chain.name))
                    else:
                        _logger.error("Failed to {} {} STS chain:\n{}\n{}".format(verb, json.dumps(
                                                                                        chain, indent=4), rsp.content))


        else:
            _logger.debug("No Security Token Service configuration found.")


    class Access_Policies(typing.TypedDict):
        '''
        Example::

                access_policies:
                - name: "MyNewAccessPolicy"
                  type: "JavaScript"
                  policy_file: "path/to/policy.file"
                  category: "OTP"

        '''

        name: str
        'A unique name for the access policy. Maximum of 256 bytes.'
        type: typing.Optional[str]
        'System default type for each access policy. For example, "JavaScript".'
        category: typing.Optional[str]
        'A grouping of related access polices. For example, category "OAUTH" identifies all the rules associated with the OAUTH flow. Maximum 256 bytes. Valid values are: "InfoMap", "AuthSVC", "OAUTH","OTP", "OIDC" and "SAML2_0".'
        policy_file: str
        'The content of the access policy.'

    def configure_access_policies(self, federation_config):
        if "access_policies" in federation_config:
            existing_policies = optional_list(self.fed.access_policy.list_policies().json)
            for policy in federation_config.access_policies:
                old_policy = optional_list(filter_list('name', policy.name, existing_policies))[0]
                rsp = None; verb = None
                methodArgs = copy.deepcopy(policy)
                policy_file = FILE_LOADER.read_file(policy.policy_file)
                del methodArgs['policy_file']
                methodArgs['content'] = policy_file['content']
                if old_policy:
                    rsp = self.fed.access_policy.update_policy(policy_id=old_policy['id'], content=methodArgs['content'])
                    verb = "updated" if rsp.success == True else "update"
                else:
                    rsp = self.fed.access_policy.create_policy(**methodArgs)
                    verb = "created" if rsp.success == True else "create"
                if rsp.success == True:
                    _logger.info("Successfully {} {} access policy.".format(verb, policy.name))
                else:
                    _logger.error("Failed to {} access policy:\n{}\n{}".format(verb, json.dumps(
                                                                                        policy, indent=4), rsp.data))


    class Alias_Service(typing.TypedDict):
        '''
        Example::

                alias_service:
                  ldap_connection: "LocalLDAP"
                  aliases:
                  - username: "mary"
                    federation_id: "https://mysp.com/isam/sps/samlsp/saml20"
                    type: "partner"
                    aliases:
                    - "mary@ibm.com"
                    - "mary@au.ibm.com"

        '''
        class Alias(typing.TypedDict):
            username: str
            'The user to associate aliases with.'
            federation: str
            'The federation this alias is for.'
            partner: typing.Optional[str]
            'Optionally, specify a partner as well as a federation.'
            type: typing.Optional[str]
            'The type of the aliases. Valid values are "self", "partner", or "old". Defaults to "self".'
            aliases: typing.List[str]
            'An array of aliases to associate with the user.'

        db_type: str
        'The alias database type, "JDBC" or "LDAP".'
        ldap_connection: str
        'The LDAP server connection name.'
        ldap_base_dn: str
        'The baseDN to search for the user entry.'
        aliases: typing.Optional[typing.List[Alias]]
        'The SAML aliases to create.'

    def configure_alias_service(self, federation_config):
        if federation_config.alias_service:
            methodArgs = copy.deepcopy(federation_config.alias_service)
            aliases = methodArgs.pop("aliases", [])
            rsp = self.fed.alias_service.update_alias_settings(**methodArgs)
            if rsp.success == True:
                _logger.info("Successfully updated the Federation Alias Service Settings.")
            else:
                _logger.error("Failed to update the Federation Alias Service Settings:\n{}\n{}".format(
                                                                json.dumps(methodArgs, indent=4), rsp.content))
            if aliases:
                existing_aliases = optional_list(self.fed.alias_service.list_alias_associations().json)
                #Map federations and partners to dict by name so we can look up the id if needed
                existing_federations = {f['name']: f for f in optional_list(self.fed.federations.list_federations())}
                for _, fed in existing_federations:
                        fed['partners'] = {p['name']: p for p in optional_list(self.fed.federations.list_partners(fed['id']))}
                for alias in aliases:
                    old_alias = optional_list(filter_list('name', alias.name, existing_aliases))[0]
                    rsp = None; verb = None
                    #Convert name to id if required
                    if alias['partner'] != None:
                        alias['federation_id'] = existing_federations.get(alias.get("federation"), "UNKNOWN") + "|" + \
                                    existing_federations.get(alias.pop("federation"), {}).get(alias.pop("partner"), "UNKNOWN")
                    else:
                        alias["federation_id"] = existing_federations.get(alias.pop("federation"), "UNKNOWN")
                    if old_alias:
                        rsp = self.fed.alias_service.update_alias_association(old_alias['id'], **alias)
                        verb = "Updated" if rsp.success == True else "Update"
                    else:
                        rsp = self.fed.alias_service.update_alias_association(**alias)
                        verb = "Created" if rsp.success == True else "Create"
                    if rsp.success == True:
                        _logger.info("Successfully {} {} alias.".format(verb, alias.name))
                    else:
                        _logger.error("Failed to {} alias:\n{}\n{}".format(
                            verb, json.dumps(alias, indent=4), rsp.content))


    class Attribute_Sources(typing.TypedDict):
        '''
        Example::

                attribute_sources:
                - name: "username"
                  type: "credential"
                  value: "PrincipalName"
                  properties:
                  - key: "searchFilter"
                    value: "(&(ObjectClass=inetOrgPerson)(memberOf=dc=ibm,dc=com))"

        '''
        class Attribute_Source(typing.TypedDict):
            class Property(typing.TypedDict):
                key: str
                'The property key. Valid fields for LDAP include "serverConnection", "scope", "selector", "searchFilter", "baseDN".'
                value: str
                'The property value.'

            name: str
            'The friendly name of the source attribute. It must be unique.'
            type: str
            '''The type of the attribute source. Valid types are:

                - "credential": The attribute is from the authenticated context.

                - "value": The attribute is plain text from the value parameter.

                - "ldap": The attribute is retrieved from an LDAP server.

            '''
            value: str
            'The value of the source attribute.\n\tCredential type: The name of a credential attribute from the authenticated context which contains the value.\n\tValue type: The plain text to be used as the source attribute value.\n\tLDAP type: The name of the LDAP attribute to be used.'
            properties: typing.Optional[typing.List[Property]]
            'The properties associated with an attribute source.'

        attribute_sources: typing.List[Attribute_Source]
        'List of attribute sources to create or update.'

    def configure_attribute_sources(self, federation_config):
        if "attribute_sources" in federation_config:
            existing_sources = optional_list(self.fed.attribute_sources.list_attribute_sources().json)
            for source in federation_config.attribute_sources:
                methodArgs = copy.deepcopy(source)
                for key in ["name", "type", "value"]:
                    if key in methodArgs:  
                        methodArgs["attribute_" + key] = methodArgs.pop(key)
                old_source = optional_list(filter_list('name', source.name, existing_sources))[0]
                rsp = None; verb = None
                if old_source:
                    rsp = self.fed.attribute_sources.update_attribute_source(old_source['id'], **methodArgs)
                    verb = "updated" if rsp.success == true else "update"
                else:
                    rsp = self.fed.attribute_sources.create_attribute_source(**methodArgs)
                    verb = "created" if rsp.success == True else "create"
                if rsp.success == True:
                    _logger.info("Successfully {} {} attribute source".format(verb, source.name))
                else:
                    _logger.error("Failed to {} attribute source:\n{}\n{}".format(
                                            verb, json.dumps(source, indent=4), rsp.content))


    def _configure_saml_partner(self, fedId, partner):
        methodArgs = {
                "name": partner.name,
                "enabled": partner.enabled,
                "role": partner.role,
                "template_name": partner.template_name
            }
        if partner.configuration != None:
            methodArgs.update({
                "access_policy": config.access_policy,
                "arti_resolution_svc": config.artifact_resolution_services,
                "assert_consume_svc": config.assertion_consumer_services,
                "attribute_mappings": config.attribute_mappings,
                "include_fed_id_in_partner_id": config.include_fed_id_in_alias_partner_id,
                "logout_request_lifetime": config.logout_request_lifetime,
                "manage_name_id_services": config.manage_name_id_services,
                "provider_id": config.provider_id,
                "session_timeout": config.session_timeout,
                "slo_svc": config.single_logout_service,
                "sso_svc": config.single_sign_on_service,
                "default_target_url": config.default_target_url,
                "anon_user_name": config.anonymous_user_name,
                "force_authn_to_federate": config.force_authn_to_federate,
                "map_unknown_alias": config.map_unknown_aliases
                })
            if config.authn_req_mapping != None:
                methodArgs.update({
                        "authn_req_delegate_id": config.authn_req_mapping.active_delegate_id,
                        "authn_req_mr": config.authn_req_mapping.mapping_rule
                    })
            if config.assertion_settings != None:
                assert_settings = config.assertion_settings
                methodArgs.update({
                        "assert_valid_before": assert_settings.valid_before,
                        "assert_valid_after": assert_settings.valid_after,
                        "assert_attribute_types": assert_settings.attribute_types,
                        "assert_session_not_after": assert_settings.session_not_after,
                        "assert_multi_attr_stmt": assert_settings.create_multiple_attribute_statements
                    })
            if config.encryption_settings != None:
                encryption = config.encryption_settings
                methodArgs.update({
                        "decrypt_key_store": encryption.decryption_key_identifier.store if encryption.decryption_key_identifier else None,
                        "decrypt_key_alias": encryption.decryption_key_identifier.label if encryption.decryption_key_identifier else None,
                        "encrypt_block_alg": encryption.block_algorithm,
                        "encrypt_transport_alg": encryption.key_transport_algorithm,
                        "encrypt_key_store": encryption.key_store,
                        "encrypt_key_alias": encryption.key_alias,
                        "encrypt_name_id": encryption.encrypt_name_id,
                        "encrypt_assertion": encryption.encrypt_assertion,
                        "encrypt_assertion_attrs": encryption.encrypt_assertion_attributes
                    })

            if config.identity_mapping != None:
                idMap = config.identity_mapping
                methodArgs.update({ "identity_delegate_id": idMap.active_delegate_id })
                if idMap.properties.mapping_rule:
                    methodArgs.update({
                            "identity_rule_type": idMap.properties.rule_type if idMap.properties.rule_type else 'JAVASCRIPT',
                            "identity_mr": idMap.properties.mapping_rule
                        })
                else:
                    methodArgs.update({
                        "identity_applies_to": idMap.properties..applies_to,
                        "identity_auth_type": idMap.properties.auth_type,
                        "identity_ba_user": idMap.properties.basic_auth_username,
                        "identity_ba_password": idMap.properties.basic_auth_password,
                        "identity_client_key_store": idMap.properties.client_key_store,
                        "identity_client_key_alias": idMap.properties.client_key_alias,
                        "identity_issuer_uri": idMap.properties.issuer_uri,
                        "identity_mgs_fmt": idMap.properties.message_format,
                        "identity_ssl_key_store": idMap.properties.ssl_key_store,
                        "identity_uri": idMap.properties.uri
                    })
            if config.extension_mapping != None:
                methodArgs.update({
                        "ext_delegate_id": config.extension_mapping.active_delegate_id,
                        "ext_mr": config.extension_mapping.mapping_rule
                    })

            if config.name_id_format != None:
                methodArgs.update({
                        "name_id_default": config.name_id_format.default,
                        "name_id_supported": config.name_id_format.supported
                    })
            if config.signature_settings != None:
                sigSetting = config.signature_settings
                methodArgs.update({
                        "sign_alg": sigSetting.signing_algorithm,
                        "sign_digest_alg": sigSetting.digest_algorithm,
                    })
                if sigSetting.key_info_elements != None:
                    methodArgs.update({
                            "sign_include_pub_key": sigSetting.key_info_elements.include_public_key,
                            "sign_include_cert": sign_include_pub_key.include_x509_certificate_data,
                            "sign_include_issuer": sign_include_pub_key.include_x509_issuer_details,
                            "sign_include_ski": sign_include_pub_key.include_x509_subject_key_identifier,
                            "sign_include_subject": sign_include_pub_key.include_x509_subject_name
                        })
                if sigSetting.signing_key_identifier != None:
                    methodArgs.update({
                            "sign_key_store": sigSetting.signing_key_identifier.store,
                            "sign_key_alias": sigSetting.signing_key_identifier.label
                        })
                if sigSetting.validation_key_identifier != None:
                    methodArgs.update({
                            "validation_key_store": ,
                            "validation_key_alias": 
                        })
                if sigSetting.signing_options != None:
                    methodArgs.update({
                            "sign_arti_request": sigSetting.signing_options.sign_artifact_request,
                            "sign_arti_rsp": sigSetting.signing_options.sign_artifact_response,
                            "sign_assertion": sigSetting.signing_options.sign_assertion,
                            "sign_authn_rsp": sigSetting.signing_options.sign_authn_response,
                            "sign_logout_req": sigSetting.signing_options.sign_logout_request,
                            "sign_logout_rsp": sigSetting.signing_options.sign_logout_response,
                            "sign_name_id_req": sigSetting.signing_options.sign_name_id_management_request,
                            "sign_name_id_rsp": sigSetting.signing_options.sign_name_id_management_response,
                            "transform_include_namespace": sigSetting.signing_options.transform_include_namespace
                        })
                if sigSetting.validation_options != None:
                    methodArgs.update({
                            "validate_assertion": sigSetting.validation_options.validate_assertion,
                            "validate_authn_req": sigSetting.validation_options.validate_authn_request,
                            "validate_arti_req": sigSetting.validation_options.validate_artifact_request,
                            "validate_arti_rsp": sigSetting.validation_options.validate_artifact_response,
                            "validate_logout_req": sigSetting.validation_options.validate_logout_request,
                            "validate_logout_rsp": sigSetting.validation_options.validate_logout_response,
                            "validate_name_id_req": sigSetting.validation_options.validate_name_id_management_request,
                            "validate_name_id_rsp": sigSetting.validation_options.validate_name_id_management_response
                        })
                if config.soap_settings != None and isinstance(config.soap_settings.server_cert_validation, dict):
                    methodArgs.update({
                            "soap_key_store": config.soap_settings.server_cert_validation.store,
                            "soap_key_alias":  config.soap_settings.server_cert_validation.label,
                            
                        })
                if config.soap_settings != None and isinstance(config.soap_settings.client_auth_data, dict):
                    methodArgs.update({
                            "soap_client_auth_method": config.soap_settings.client_auth_data.method,
                            "soap_client_auth_ba_user": config.soap_settings.client_auth_data.basic_auth_username,
                            "soap_client_auth_ba_password": config.soap_settings.client_auth_data.basic_auth_password,
                            "soap_client_auth_key_store": config.soap_settings.client_auth_data.client_key_store,
                            "soap_client_auth_key_alias": config.soap_settings.client_auth_data.client_key_alias
                        })
        rsp = self.fed.federations.create_saml_partner(fedId, **methodArgs)
        if rsp.success == True:
            _logger.info("Successfully created {} {} SAML Partner".format(
                partner.name, partner.role))
        else:
            _logger.error("Failed to create {} SAML Partner with config:\n{}\n{}".format(
                                        partner.name, json.dumps(partner, indent=4), rsp.content))

    def _configure_oidc_partner(self, fedId, partner):
        methodArgs = {
                "name": partner.name,
                "enabled": partner.enabled,
                "template_name": partner.template_name
            }
        if partner.configuration != None:
            config = partner.configuration
            methodArgs.update({
                    "redirect_uri_prefix": config.redirect_uri_prefix,
                    "response_type": config.response_types,
                    "attribute_mapping": config.attribute_mapping
                })
            if config.basic_configuration:
                methodArgs.update({
                        "active_delegate_id": config.basic_configuration.active_delegate_id,
                        "metadata_endpoint_url": config.basic_configuration.metadata_endpoint_url,
                        "issuer_identifier": config.basic_configuration.issuer_identifier,
                        "response_types": config.basic_configuration.response_types,
                        "authorization_endpoint": config.basic_configuration.authorization_endpoint_url,
                        "token_endpoint": config.basic_configuration.token_endpoint_url,
                        "user_info_endpoint": config.basic_configuration.user_info_endpoint_url
                    })
            if config.identity_mapping and config.identity_mapping.properties:
                methodArgs.update({
                        "identity_delegate_id": config.identity.active_delegate_id,
                        "identity_mapping_rule": config.identity.properties.mapping_rule,
                        "identity_auth_type": config.identity_mapping.properties.auth_type,
                        "identity_ba_user": config.identity_mapping.properties.basic_auth_username,
                        "identity_ba_password": config.identity_mapping.properties.basic_auth_password,
                        "identity_client_keystore": config.identity_mapping.properties.client_key_store,
                        "identity_client_key_alias": config.identity_mapping.properties.client_key_alias,
                        "identity_issuer_uri": config.identity_mapping.properties.issuer_uri,
                        "identity_msg_fmt": config.identity_mapping.properties.message_format,
                        "identity_ssl_keystore": config.identity_mapping.properties.ssl_keystore,
                        "identity_uri": config.identity_mapping.properties.uri
                    })                    

            if config.advanced_configuration != None:
                methodArgs.update({
                        "advanced_configuration_active_delegate": config.advanced_configuration.active_delegate_id,
                        "advanced_configuration_rule_id": config.advanced_configuration.mapping_rule,
                        "advanced_configuration_rule_type": config.advanced_configuration.rule_type if config.advanced_configuration.rule_type else "JAVASCRIPT"
                    })

        rsp = self.fed.federations.create_oidc_rp_partner(fedId, **methodArgs)
        if rsp.success == True:
            _logger.info("Successfully created {} OIDC RP Partner for Federation {}".format(
                partner.name, fedId))
        else:
            _logger.error("Failed to create {} OIDC RP Partner with config:\n{}/n{}".format(
                partner.name, json.dumps(partner, indent=4), rsp.data))

    def _configure_federation_partner(self, federation, partner):
        federationId = None
        _federations = self.fed.federations.list_federations().json
        for _federation in _federations:
            if _federation.get("name", None) == federation.name:
                federationId = _federation['id']
        method = {"ip": _configure_saml_partner,
                  "sp": _configure_saml_partner,
                  "rp": _configure_oidc_partner
                }.get(partner.role, None)
        if method == None:
            _logger.error("Federation partner {} does not specify a valid configuration: {}\n\tskipping . . .".format(
                partner.name, json.dumps(partner, indent=4)))
        else:
            method(federationId, partner)

    def _configure_saml_federation(self, federation):
        methodArgs = {
                    "name": federation.name,
                    "role": federation.role,
                    "template_name": federation.template_name,
                }
        if federation.configuration != None:
            config = federation.configuration
            methodArgs.update({
                    "access_policy": config.access_policy,
                    "artifact_lifetime": config.artifact_lifetime,
                    "artifact_resolution_service": config.artifact_resolution_services,
                    "attribute_mapping": config.attribute_mappings,
                    "company_name": config.company_name,
                    "manage_name_id_services": config.manage_name_id_services
                    "msg_valid_time": config.message_valid_time,
                    "msg_issuer_fmt": config.message_issuer_format,
                    "msg_issuer_name_qualifier": config.message_issuer_name_qualifier,
                    "consent_to_federate": config.need_consent_to_federate,
                    "exclude_session_index_logout_request": config.exclude_session_index_in_single_logout_request,
                    "poc_url": config.point_of_contact_url,
                    "provider_id": config.provider_id,
                    "session_timeout": config.session_timeout,
                    "sso_svc_data": config.single_sign_on_service,
                    "slo_svc_data": config.single_logout_service,
                    "assertion_consume_svc": config.assertion_consumer_services
                })

            if config.name_id_format != None:
                methodArgs.update({
                        "name_id_default": config.name_id_format.default,
                        "name_id_supported": config.name_id_format.supported
                    })

            if config.encryption_settings != None:
                methodArgs.update({
                        "encrypt_block_alg": config.encryption_settings.block_algorithm,
                        "encrypt_key_transport_alg": config.encryption_settings.key_transport_algorithm,
                        "encrypt_key_alias": config.encryption_settings.key_alias,
                        "encrypt_key_store": config.encryption_settings.key_store,
                        "encrypt_name_id": config.encryption_settings.encrypt_name_id,
                        "encrypt_assertions": config.encryption_settings.encrypt_assertions,
                        "encrypt_assertion_attrs": config.encryption_settings.encrypt_assertion_attributes,
                        "decrypt_key_alias": config.encryption_settings.decryption_key_identifier.label if encryption.decryption_key_identifier else None,
                        "decrypt_key_store": config.encryption_settings.decryption_key_identifier.store if encryption.decryption_key_identifier else None
                    })

            if config.assert_settings != None:
                methodArgs.update({
                        "assertion_attr_types": config.assert_settings.attribute_types,
                        "assertion_session_not_on_or_after": config.assert_settings.session_not_on_or_after,
                        "assertion_multi_attr_stmt": config.assert_settings.create_multiple_attribute_statements,
                        "assertion_valid_before": config.assert_settings.assertion_valid_before,
                        "assertion_valid_after": config.assert_settings.assertion_valid_after
                    })
            if config.identity_mapping != None and config.identity_mapping.properties != None:
                methodArgs.update({
                        "identity_delegate_id": config.identity_mapping.active_delegate_id,
                        "identity_rule_id": config.identity_mapping.properties.mapping_rule,
                        "identity_rule_type": config.identity_mapping.properties.rule_type if config.identity_mapping.properties.rule_type else 'JAVASCRIPT',
                        "identity_applies_to": config.identity_mapping.properties.applies_to,
                        "identity_auth_type": config.identity_mapping.properties.auth_type,
                        "identity_ba_user": config.identity_mapping.properties.basic_auth_username,
                        "identity_ba_password": config.identity_mapping.properties.basic_auth_password,
                        "identity_client_keystore": config.identity_mapping.properties.client_key_store,
                        "identity_client_key_alias": config.identity_mapping.properties.client_key_alias,
                        "identity_issuer_uri": config.identity_mapping.properties.issuer_uri,
                        "identity_msg_fmt": config.identity_mapping.properties.message_format,
                        "identity_ssl_keystore": config.identity_mapping.properties.ssl_key_store,
                        "identity_uri": config.identity_mapping.properties.uri
                    })
            if config.extension_mapping != None:
                methodArgs.update({
                        "ext_delegate_id": config.extension_mapping.active_delegate_id,
                        "ext_mapping_rule": config.extension_mapping.mapping_rule
                    })
            if config.signature_settings != None:
                sigSetting = config.signature_settings
                methodArgs.update({
                        "sign_alg": sigSetting.signature_algorithm,
                        "sign_digest_alg": sigSetting.digest_algorithm,
                        "transform_include_namespace": sigSetting.include_inclusive_namespaces,
                        "validate_assertion": sigSetting.validate_assertion
                    })
                if sigSettings.key_info_elements != None:
                    methodArgs.update({
                            "sign_include_cert": sigSettings.key_info_elements.include_x509_certificate_data,
                            "sign_include_subject": sigSettings.key_info_elements.include_x509_subject_name,
                            "sign_include_ski": sigSettings.key_info_elements.include_x509_subject_key_identifier,
                            "sign_include_issuer": sigSettings.key_info_elements.include_x509_issuer_details,
                            "sign_include_pubkey": sigSettings.key_info_elements.include_public_key
                        })
                if sigSettings.signing_key_identifier != None:
                    methodArgs.update({
                            "signing_keystore": sigSettings.signing_key_identifier.keystore,
                            "sign_key_alias": sigSettings.signing_key_identifier.certificate
                        })
                if sigSetting.validation_key_identifier != None:
                    methodArgs.update({
                            "sign_valid_key_store": sigSettings.validation_key_identifier.keystore,
                            "sign_valid_key_alias": sigSettings.validation_key_identifier.certificate
                        })
                if sigSettings.signing_options != None:
                    methodArgs.update({
                            "sign_assertion": sigSettings.signing_options.sign_assertion,
                            "sign_auth_rsp": sigSettings.signing_options.sign_authn_response,
                            "sign_arti_req": sigSettings.signing_options.sign_artifact_request,
                            "sign_arti_rsp": sigSettings.signing_options.sign_artifact_response,
                            "sign_logout_req": sigSettings.signing_options.sign_logout_request,
                            "sign_logout_rsp": sigSettings.signing_options.sign_logout_response,
                            "sign_name_id_req": sigSettings.signing_options.sign_name_id_management_request,
                            "sign_name_id_rsp": sigSettings.signing_options.sign_name_id_management_response
                        })
                if sigSettings.validation_options != None:
                    methodArgs.update({
                            "validate_auth_req": sigSettings.validation_options.validate_authn_request,
                            "validate_assert": sigSettings.validation_options.validate_assertion,
                            "validate_arti_req": sigSettings.validation_options.validate_artifact_request,
                            "validate_arti_rsp": sigSettings.validation_options.validate_artifact_response,
                            "validate_logout_req": sigSettings.validation_options.validate_logout_request,
                            "validate_logout_rsp": sigSettings.validation_options.validate_logout_response,
                            "validate_name_id_req": sigSettings.validation_options.validate_name_id_management_request
                            "validate_name_id_rsp": sigSettings.validation_options.validate_name_id_management_response
                        })
            if config.alias_service_settings != None:
                methodArgs.update({
                        "alias_svc_db_type": config.alias_service_settings.db_type,
                        "alias_svc_ldap_con": config.alias_service_settings.ldap_connection,
                        "alias_svc_ldap_base_dn": config.alias_service_settings.ldap_base_dn
                    })
            
            if config.authn_req_mapping != None:
                methodArgs.update({
                        "authn_req_delegate_id": config.authn_req_mapping.active_delegate_id,
                        "authn_req_mr": config.authn_req_mapping.mapping_rule
                    })
            
        rsp = self.fed.federations.create_saml_federation(**methodArgs)
        if rsp.success == True:
            _logger.info("Successfully created {} SAML2.0 Federation".format(federation.name))
        else:
            _logger.error("Failed to create {} SAML2.0 Federation with config:\n{}\n{}".format(
                federation.name, json.dumps(federation, indent=4), rsp.data))
            return
        if federation.partners != None:
            for partner in federation.partners:
                _create_partner(federation, partner)


    def _configure_oidc_federation(self, federation):
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
                    "attribute_mapping": config.attribute_mappings
                })
            if config.identity_mapping != None and config.identity_mapping.properties != None:
                methodArgs.update({
                        "identity_mapping_delegate_id": config.identity_mapping.active_delegate_id,
                        "identity_mapping_rule": config.identity_mapping.properties.mapping_rule,
                        "identity_auth_type": config.identity_mapping.properties.auth_type,
                        "identity_ba_user": config.identity_mapping.properties.basic_auth_username,
                        "identity_ba_password": config.identity_mapping.properties.basic_auth_password,
                        "identity_client_keystore": config.identity_mapping.properties.client_key_store,
                        "identity_client_key_alias": config.identity_mapping.properties.client_key_alias,
                        "identity_issuer_uri": config.identity_mapping.properties.issuer_uri
                        "identity_message_format": config.identity_mapping.properties.message_format
                        "identity_ssl_keystore": config.identity_mapping.properties.ssl_key_store,
                        "identity_uri": config.identity_mapping.properties.uri
                    })
            if config.advance_configuration != None:
                methodArgs.update({
                        "adv_delegate_id": config.advance_configuration.active_delegate_id,
                        "adv_mapping_rule": config.advance_configuration.mapping_rule,
                        "adv_rule_type": config.advance_configuration.rule_type if config.advance_configuration.rule_type != None else "JAVASCRIPT"
                    })
        rsp = self.fed.federations.create_oidc_rp_federation(**methodArgs)
        if rsp.success == True:
            _logger.info("Successfully created {} OIDC RP Federation".format(federation.name))
        else:
            _logger.error("Failed to create {} OIDC RP Federation with config:\n{}\n{}".format(
                    federation.name, json.dumps(federation, indent=4), rsp.data))
            if federation.partners != None:
                for partner in federation.partners:
                    _create_partner(federation, partner)


    class Federations(typing.TypedDict):
        '''
        Example::

                TO: DO

        '''
        class Federation(typing.TypedDict):

            class SAML20_Identity_Provider(typing.TypedDict):

                access_policy: typing.Optional[str]
                'The access policy that should be applied during single sign-on.'
                artifact_lifetime: typing.Optional[int]
                'The number of seconds that an artifact is valid. The default value is 120. This setting is enabled only when HTTP artifact binding has been enabled.'
                assertion_settings: typing.Optional[Federation_Common.Assertion_Settings]
                'The assertion settings.'
                artifact_resolution_services: typing.Optional[typing.List[Federation_Common.Artifact_Resolution_Service]]
                'Endpoints where artifacts are exchanged for actual SAML messages. Required if artifact binding is enabled.'
                attribute_mappings: typing.Optional[Federation_Common.Attribute_Mapping]
                'The attribute mapping data.'
                company_name: str
                'The name of the company that creates the identity provider or service provider.'
                encryption_settings: typing.Optional[Federation_Common.Encryption_Settings]
                'The encryption and decryption configurations for SAML messages.'
                identity_mapping: Federation_Common.Identity_Mapping
                'The identity mapping data.'
                extension_mapping: Federation_Common.Extension_Mapping
                'The extension mapping data.'
                manage_name_id_services: typing.Optional[typing.List[Federation_Common.Service_Data]]
                'Endpoints that accept SAML name ID management requests or responses.'
                message_valid_time: typing.Optional[int]
                'The number of seconds that a message is valid. The default value is 300.'
                message_issuer_format: typing.Optional[str]
                'The format of the issuer of SAML message. The default value is "urn:oasis:names:tc:SAML:2.0:nameid-format:entity".'
                message_issuer_name_qualifier: typing.Optional[str]
                'The name qualifier of the issuer of SAML messaged.'
                name_id_format: typing.Optional[Federation_Common.Name_Id_Format]
                'The name identifier format configurations.'
                need_consent_to_federate: typing.Optional[bool]
                'A setting that specifies whether to ask user\'s consent before linking the account. The default value is ``true``.'
                exclude_session_index_in_single_logout_request: typing.Optional[bool]
                'A setting that specifies whether the LogoutRequest messages sent out from this entity will exclude SessionIndex during IP init SLO flow. The default value is ``false``.'
                point_of_contact_url: str
                'The endpoint URL of the point of contact server. The point of contact server is a reverse proxy server that is configured in front of the runtime listening interfaces. The format is "http[s]://hostname[:portnumber]/[junction]/sps".'
                provider_id: typing.Optional[str]
                'A unique identifier that identifies the provider to its partner provider. If not provided or an empty string is provided, the default value is "<point of contact URL>/<federation name>/saml20".'
                session_timeout: typing.Optional[int]
                'The number of seconds that the SAML session remains valid. The default value is 7200.'
                signature_settings: typing.Optional[Federation_Common.Signature_Settings]
                'The signing and validation configurations for SAML messages and assertions.'
                single_sign_on_service: typing.Optional[typing.List[Federation_Common.Single_Sign_On_Service]]
                'Endpoints at an Identity Provider that accept SAML authentication requests.'
                single_logout_service: typing.Optional[typing.List[Federation_Common.Service_Data]]
                'Endpoints that accept SAML logout requests or responses.'
                alias_service_settings: typing.Optional[Federation_Common.Alias_Service_Settings]
                'The alias service settings to store the user alias.'

            class SAML20_Service_Provider(typing.TypedDict):

                artifact_lifetime: typing.Optional[int]
                'The number of seconds that an artifact is valid. The default value is 120. This setting is enabled only when HTTP artifact binding has been enabled.'
                assertion_consumer_services: typing.List[Federation_Common.Assertion_Consumer_Service]
                'Endpoints at a Service Provider that receive SAML assertions.'
                artifact_resolution_services: typing.List[Federation_Common.Artifact_Resolution_Service]
                'Endpoints where artifacts are exchanged for actual SAML messages. Required if artifact binding is enabled.'
                attribute_mappings: typing.Optional[Federation_Common.Attribute_Mapping]
                'The attribute mapping data.'
                company_name: str
                'The name of the company that creates the identity provider or service provider.'
                encryption_settings: typing.Optional[Federation_Common.Encryption_Settings]
                'The encryption and decryption configurations for SAML messages.'
                identity_mapping: Federation_Common.Identity_Mapping
                'The identity mapping data.'
                extension_mapping: Federation_Common.Extension_Mapping
                'The extension mapping data.'
                authn_req_mapping: Federation_Common.Authn_Req_Mapping
                'The authentication request mapping data.'
                manage_name_id_services: typing.Optional[typing.List[Federation_Common.Service_Data]]
                'Endpoints that accept SAML name ID management requests or responses.'
                message_valid_time: typing.Optional[int]
                'The number of seconds that a message is valid. The default value is 300.'
                message_issuer_format: typing.Optional[str]
                'The format of the issuer of SAML message. The default value is "urn:oasis:names:tc:SAML:2.0:nameid-format:entity".'
                message_issuer_name_qualifier: typing.Optional[str]
                'The name qualifier of the issuer of SAML messaged.'
                name_id_format: typing.Optional[Federation_Common.Name_Id_Format]
                'The name identifier format configurations.'
                point_of_contact_url: str
                'The endpoint URL of the point of contact server. The point of contact server is a reverse proxy server that is configured in front of the runtime listening interfaces. The format is "http[s]://hostname[:portnumber]/[junction]/sps".'
                provider_id: typing.Optional[str]
                'A unique identifier that identifies the provider to its partner provider. If not provided or an empty string is provided, the default value is "<point of contact URL>/<federation name>/saml20".'
                session_timeout: typing.Optional[int]
                'The number of seconds that the SAML session remains valid. The default value is 7200.'
                signature_settings: typing.Optional[Federation_Common.Signature_Settings]
                'The signing and validation configurations for SAML messages and assertions.'
                single_logout_service: typing.Optional[typing.List[Federation_Common.Service_Data]]
                'Endpoints that accept SAML logout requests or responses.'
                alias_service_settings: typing.Optional[Federation_Common.Alias_Service_Settings]
                'The alias service settings to store the user alias.'

            class SAML20_Identity_Provider_Partner(typing.TypedDict):

                access_policy: typing.Optional[str]
                'The access policy that should be applied during single sign-on.'
                artifact_resolution_services: typing.Optional[Federation_Common.Artifact_Resolution_Service]
                'Partner\'s endpoints where artifacts are exchanged for actual SAML messages. Required if artifact binding is enabled.'
                assertion_consumer_services: typing.List[Federation_Common.Assertion_Consumer_Service]
                'Partner\'s endpoints that receive SAML assertions.'
                assertion_settings: Federation_Common.Assertion_Settings
                'The assertion settings.'
                attribute_mappings: typing.Optional[Federation_Common.Attribute_Mapping]
                'The attribute mapping data.'
                encryption_settings: typing.Optional[Federation_Common.Encryption_Settings]
                'The encryption and decryption configurations for SAML messages.'
                identity_mapping: typing.Optional[Federation_Common.Identity_Mapping]
                'The identity mapping data.'
                extension_mapping: Federation_Common.Extension_Mapping
                'The extension mapping data.'
                include_fed_id_in_alias_partner_id: typing.Optional[bool]
                'A setting that specifies whether to append federation ID to partner ID when mapping user aliases. The default value is false.'
                logout_request_lifetime: typing.Optional[int]
                'A setting that specifies Logout request lifetime in number of seconds. If not provided, the default value is 120.'
                manage_name_id_services: typing.Optional[typing.List[Federation_Common.Service_Data]]
                'Partner\'s endpoints that accept SAML name ID management requests or responses.'
                name_id_format: typing.Optional[Federation_Common.Name_Id_Format]
                'The name identifier format configurations.'
                provider_id: str
                'A unique identifier that identifies the partner.'
                signature_settings: typing.Optional[Federation_Common.Signature_Settings]
                'The signing and validation configurations for SAML messages and assertions.'
                single_logout_service: typing.Optional[Federation_Common.Service_Data]
                'Partner\'s endpoints that accept SAML logout requests or responses.'
                soap_settings: typing.Optional[Federation_Common.SOAP_Settings]
                'A setting that specifies the connection parameters for the SOAP endpoints.'

            class SAML20_Service_Provider_Partner(typing.TypedDict):
                anonymous_user_name: typing.Optional[str]
                'This is a one-time name identifier that allows a user to access a service through an anonymous identity. The user name entered here is one that the service provider will recognize as a one-time name identifier for a legitimate user in the local user registry.'
                artifact_resolution_services: typing.Optional[Federation_Common.Artifact_Resolution_Service]
                'Partner\'s endpoints where artifacts are exchanged for actual SAML messages. Required if artifact binding is enabled.'
                assertion_settings: typing.Optional[Federation_Common.Assertion_Settings]
                'The assertion settings.'
                attribute_mappings: typing.Optional[Federation_Common.Attribute_Mapping]
                'The attribute mapping data.'
                encryption_settings: typing.Optional[Federation_Common.Encryption_Settings]
                'The encryption and decryption configurations for SAML messages.'
                force_authn_to_federate: typing.Optional[bool]
                'A setting that specifies whether to force user to authenticate before linking the account.'
                identity_mapping: typing.Optional[Federation_Common.Identity_Mapping]
                'The identity mapping data.'
                extension_mapping: typing.Optional[Federation_Common.Extension_Mapping]
                'The extension mapping data.'
                authn_req_mapping: Federation_Common.Authn_Req_Mapping
                'The authentication request mapping data.'
                include_fed_id_in_alias_partner_id: typing.Optional[bool]
                'A setting that specifies whether to append federation ID to partner ID when mapping user aliases.'
                manage_name_id_services: typing.Optional[typing.List[Federation_Common.Service_Data]]
                'Partner\'s endpoints that accept SAML name ID management requests or responses.'
                map_unknown_aliases: typing.Optional[bool]
                'A setting that specifies whether to map non-linked persistent name ID to one-time username.'
                name_id_format: typing.Optional[Federation_Common.Name_Id_Format]
                'The name identifier format configurations.'
                provider_id: str
                'A unique identifier that identifies the partner.'
                signature_settings: typing.Optional[Federation_Common.Signature_Settings]
                'The signing and validation configurations for SAML messages and assertions.'
                single_logout_service: typing.Optional[typing.List[Federation_Common.Service_Data]]
                'Partner\'s endpoints that accept SAML logout requests or responses.'
                single_sign_on_service: typing.Optional[typing.List[Federation_Common.Single_Sign_On_Service]]
                'Partner\'s endpoints that accept SAML authentication requests.'
                soap_settings: typing.Optional[Federation_Common.SOAP_Settings]
                'A setting that specifies the connection parameters for the SOAP endpoints.'
                default_target_url: typing.Optional[str]
                'Default URL where end-user will be redirected after the completion of single sign-on. '

            class OIDC_Relying_Party(typing.TypedDict):

                redirect_uri_prefix: str
                'The reverse proxy address to prepend to the redirect URI sent to the provider to communicate with this instance. An example is "https://www.reverse.proxy.com/mga". For the value "https://www.reverse.proxy.com/mga", the kickoff uri would be: "https://www.reverse.proxy.com/mga/sps/oidc/rp/<FEDERATION_NAME>/kickoff/<PARTNER_NAME>" and the redirect uri: "https://www.reverse.proxy.com/mga/sps/oidc/rp/<FEDERATION_NAME>/redirect/<PARTNER_NAME>"'
                response_types: typing.List[str]
                'List of response types which determine the flow to be executed. Valid values to be included are "code", "token", "id_token". This selects the default flow to run when a metadata URL is specified in the partner configuration.'
                attribute_mappings: typing.Optional[Federation_Common.Attribute_Mapping]
                'The attribute mapping data.'
                identity_mapping: Federation_Common.Identity_Mapping
                'The identity mapping data.'
                advanced_configuration: Federation_Common.Advanced_Configuration
                'The advanced configuration data.'

            class OIDC_Relying_Party_Partner(typing.TypedDict):

                client_id: str
                'The ID that identifies this client to the provider.'
                client_secret: typing.Optional[str]
                'The secret associated with the client ID. Do not include if creating a public client.'
                basic_configuration: Federation_Common.Basic_Configuration
                'The basic configuration data.'
                signature_algorithm: typing.Optional[str]
                'The signing algorithm to use. Supported values are "none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512".'
                verification_keystore: typing.Optional[str]
                'When signature algorithm requires a certificate, the keystore which contains the selected certificate to perform the signing.'
                verification_key_label: typing.Optional[str]
                'When signature algorithm requires a certificate, the alias of the public key in the selected keystore to use in signature verification.'
                jwks_endpoint_url: typing.Optional[str]
                'When signature algorithm requires a certificate, the JWK endpoint of the provider. If a metadata endpoint is specified in BasicConfigurationData, the JWK URL will be read from metadata information. Cannot be specified if using a signingKeyLabel.'
                key_management_algorithm: typing.Optional[str]
                'The key management algorithm to use. Supported values are "none", "dir", "A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW", "RSA1_5", "RSA-OAEP", "RSA-OAEP-256".'
                content_encryption_algorithm: typing.Optional[str]
                'The content encryption algorithm to use. Supported values are "none", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM".'
                decryption_keystore: typing.Optional[str]
                'When key management algorithm requires a certificate, the keystore which contains the selected certificate to perform JWT decryption.'
                decryption_key_label: typing.Optional[str]
                'When key management algorithm requires a certificate, the alias of the private key in the selected keystore to perform JWT decryption.'
                scope: typing.Optional[typing.List[str]]
                'An array of strings that identify the scopes to request from the provider. Defaults to ["openid"].'
                perform_user_info: typing.Optional[bool]
                'A setting that specifies whether to perform user info request automatically whenever possible.'
                token_endpoint_auth_method: str
                'The token endpoint authentication method. Valid values are "client_secret_basic" and "client_secret_post".'
                attribute_mappings: typing.Optional[Federation_Common.Attribute_Mapping]
                'The attribute mapping data.'
                identity_mapping: typing.Optional[Federation_Common.Identity_Mapping]
                'The identity mapping data.'
                advance_configuration: typing.Optional[Federation_Common.Advanced_Configuration]
                'The advance configuration data. '

            class WSFed_Identity_Provider(typing.TypedDict):

                assertion_settings: typing.Optional[Federation_Common.Assertion_Settings]
                'The assertion settings.'
                company_name: typing.Optional[str]
                'The name of the company that creates the identity provider or service provider.'
                identity_mapping: Federation_Common.Identity_Mapping
                'The identity mapping data.'
                point_of_contact_url: str
                'The endpoint URL of the point of contact server. The point of contact server is a reverse proxy server that is configured in front of the runtime listening interfaces. The format is "http[s]://hostname[:portnumber]/[junction]/sps".'
            
            class WSFed_Service_Provider(typing.TypedDict):

                company_name: str
                'The name of the company that creates the identity provider or service provider.'
                identity_mapping: Federation_Common.Identity_Mapping
                'The identity mapping data.'
                point_of_contact_url: str
                'The endpoint URL of the point of contact server. The point of contact server is a reverse proxy server that is configured in front of the runtime listening interfaces. The format is "http[s]://hostname[:portnumber]/[junction]/sps".'
                replay_validation: bool
                'Whether to enable one-time assertion use enforcement.'
            
            class WSFed_Identity_Provider_Partner(typing.TypedDict):

                attribute_types: typing.Optional[typing.List[str]]
                'Specifies the types of attributes to include in the assertion. The default, an asterisk (*), includes all the attribute types that are specified in the identity mapping file.'
                endpoint: str
                'The endpoint of the WS-Federation partner.'
                identity_mapping: Federation_Common.Identity_Mapping
                'The identity mapping data.'
                include_certificate_data: typing.Optional[bool]
                'Whether to include the BASE64 encoded certificate data with the signature. Defaults to true if not specified.'
                include_issuer_details: typing.Optional[bool]
                'Whether to include the issuer name and the certificate serial number with the signature. Defaults to false if not specified.'
                include_public_key: typing.Optional[bool]
                'Whether to include the public key with the signature. Defaults to false if not specified.'
                include_subject_key_identifier: typing.Optional[bool]
                'Whether to include the X.509 subject key identifier with the signature. Defaults to false if not specified.'
                include_subject_name: typing.Optional[bool]
                'Whether to include the subject name with the signature. Defaults to false if not specified.'
                max_request_lifetime: int
                'The amount of time that the request is valid (in milliseconds).'
                realm: str
                'The realm of the WS-Federation partner.'
                signature_algorithm: typing.Optional[str]
                'The signature algorithm to use for signing SAML assertions. Must be one of: "RSA-SHA1", "RSA-SHA256" or "RSA-SHA512". Only required if signSamlAssertion is set to tru'
                signing_key_identifier: typing.Optional[Federation_Common.Key_Identifier]
                'The certificate to use for signing the SAML assertions. Only required if signSamlAssertion is set to true.'
                sign_saml_assertion: typing.Optional[bool]
                'Whether or not the assertion needs to be signed.'
                subject_confirmation_method: typing.Optional[str]
                'The subject confirmation method. Must be one of: "No Subject Confirmation Method", "urn:oasis:names:tc:SAML:1.0:cm:bearer", "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key" or "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches".'
                use_inclusive_namespace: typing.Optional[bool]
                'Whether or not to use the InclusiveNamespaces construct. Defaults to true if not specified. '

            class WSFed_Service_provider_Partner(typing.TypedDict):

                endpoint: str
                'The endpoint of the WS-Federation partner.'
                identity_mapping: Federation_Common.Identity_Mapping
                'The identity mapping data.'
                key_alias: typing.Optional[Federation_Common.Key_Identifier]
                'The keystore and certificate to use to validate the signature. Only required if verifySignatures is set to true and useKeyInfo is set to false.'
                key_info: typing.Optional[str]
                'The regular expression used to find the X509 certificate for signature validation. Only required if verifySignatures is set to true and useKeyInfo is set to true.'
                max_request_lifetime: int
                'The amount of time that the request is valid (in milliseconds).'
                realm: str
                'The realm of the WS-Federation partner.'
                use_key_info: typing.Optional[bool]
                'Whether to use the keyInfo of the XML signature to find the X509 certificate for signature validation (true) or the specified keyAlias (false). Only required if verifySignatures is set to true.'
                verify_signatures: typing.Optional[bool]
                'Whether to enable signature validation. Defaults to false if not specified.'
                want_multiple_attribute_statements: bool
                'Whether to create multiple attribute statements in the Universal User.'

            name: str
            'A meaningful name to identify this federation.'
            protocol: str
            'The name of the protocol to be used in the federation. Valid values are "SAML2_0" and "OIDC10".'
            role: str
            'The role of a federation: "ip" for a SAML 2.0 identity provider federation, and "sp" for a SAML 2.0 service provider federation. Use "op" for an OpenID Connect Provider federation, and "rp" for an OpenID Connect Relying Party federation.'
            template_name: typing.Optional[str]
            'An identifier for the template on which to base this federation'
            configuration: typing.Union[SAML20_Identity_Provider, SAML20_Service_Provider, OIDC_Relying_Party, WSFed_Identity_Provider, WSFed_Service_Provider]
            'The protocol-specific configuration data. The contents of this JSON object will be different for each protocol.'
            partners: typing.Optional[typing.Union[SAML20_Identity_Provider_Partner, SAML20_Service_Provider_Partner, OIDC_Relying_Party_Partner, WSFed_Identity_Provider_Partner]]
            'List of federation partners to create for each federations.'
            import_partners: typing.Optional[typing.List[str]]
            'List of XML metadata documents which define partners for a configured Federation.'

        federations: typing.List[Federation]
        'List of federations and associated partner properties.'

    def configure_federations(self, federation_config):
        if federation_config.federations != None:
            for federation in federations:
                method = {"SAML2_0": _configure_saml_federation,
                          "OIDC10": _configure_oidc_federation
                          }.get(federation.protocol, None)
                if method == None:
                    _logger.error("Federation {} does not specify a valid configuration: {}\n\tskipping . . .".format(
                        federation.name, json.dumps(federation, indent=4)))
                    continue
                else:
                    method(federation)
                if federation.webseal:
                    #Run the WebSEAL config wizard
                    methodArgs = {
                            "federation_id": fed_uuid,
                            "reuse_acls": federation.webseal.reuse_acls,
                            "reuse_certs": federation.webseal.reuse_certs
                        }
                    if federation.webseal.runtime:
                        methodArgs.update({
                                            "runtime_hostname": federation.webseal.runtime.hostname,
                                            "runtime_port": federation.webseal.runtime.port,
                                            "runtime_username": federation.webseal.runtime.username,
                                            "runtime_password": federation.webseal.runtime.password
                                        })
                    rsp = self.factory.get_web_settings().reverse_proxy.configure_fed(
                                                                                federation.webseal.name, **methodArgs);
                    if rsp.success == True:
                        _logger.info("Successfully ran WebSEAL configuration for {} Federation on the {} reverse"
                                     "proxy instance".format(federation.name, federation.webseal.name))
                    else:
                        _logger.error("Failed to run WebSEAL fed config  wizard for {} on reverse proxy instance {}"
                                    "with config:\n{}\n{}".format(federation.name, federation.webseal.name, 
                                                                  json.dumps(federation, indent=4), rsp.data))



    def configure(self):
        if self.config.federation == None:
            _logger.info("No Federation configuration detected, skipping")
            return
        self.configure_poc(self.config.federation)
        self.configure_sts(self.config.federation)
        self.configure_access_policies(self.config.federation)
        self.configure_alias_service(self.config.federation)
        self.configure_attribute_sources(self.config.federation)
        self.configure_federations(self.config.federation)

if __name__ == "__main__":
    configure()
