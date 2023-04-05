Federations Configuration
#########################
The Federation module is used to integrate Verify Access with third party applications to provide or 
accept identity information. This module can be use fro both: supplying third party applications with 
identity information (Verify Access is the identity source); or accepting identity information (Verify 
Access is the identity consumer).

Integration with third party applications is achieved via Identity standards, such as OIDC or SAML 2.0.


Example
=======

.. code-block:: yaml

                attribute_sources:
                - name: "SF_IDPEmail"
                  type: "value"
                  value: "user@verify-demoer-dev-ed.salesforce.com"
                - name: "IDPEmail"
                  type: "value"
                  value: "user@verify.securitypoc.com"
                - name: "ImmutableID"
                  type: "value"
                  value: "verifytestuser"
                federations:
                - name: "SP-SAML-QC"
                  protocol: "SAML2_0"
                  template_name: "QuickConnect"
                  point_of_contact_url: "https://www.myidp.ibmsec/isva"
                  provider_id: ""
                  decrypt_keystore: "rt_profile_keys"
                  decrypt_key_label: "server"
                  signing_keystore: "rt_profile_keys"
                  signing_key_label: "runtime"
                  sso_service_binding: "redirect"
                  partners:
                  - name: "Salesforce"
                    role: "sp"
                    client_auth_method: "none"
                    template_name: "Salesforce_JIT_Provisioning_Disabled"
                    enabled: true
                    acs:
                      binding: "post"
                      default: true
                      index: 0
                      url: "https://verify-demoer-dev-ed.my.salesforce.com"
                    validate_authn_request: true
                    validation:
                      keystore: "rt_profile_keys"
                      key_label: "Verify_19.crt"
                    attribute_mapping:
                      name: "IDP_Email"
                      source: "3"
                    active_delegate_id: "default-map"
                    provider_id: "https://verify-demoer-dev-ed.my.salesforce.com"
                    signature_validation: false
                    mapping_rule: "mapping/rules/federations/adv_attribute_mapping.js"
                  - name: "Micrsoft Office 365"
                    template_name: "Office_365"
                    role: "sp"
                    enabled: true
                    acs:
                      binding: "post"
                      default: true
                      index: "0"
                      url: "https://login.microsoftonline.com/login.srf"
                    validate_authn_request: false
                    attribute_mapping:
                    - name: "IDPEmail"
                      source: "1"
                    - name: "ImmutableID"
                      source: "2"
                    active_delegate_id: "default-map"
                    provider_id: "urn:federation:MicrosoftOnline"
                    signature_validation: false
                    mapping_rule: "mapping/rules/federations/adv_attribute_mapping.js"
                               - name: "SP-SAML-CIC"
                  role: "ip"
                  protocol: "SAML2_0"
                  provider_id: ""
                  point_of_contact_url: "https://www.myidp.ibmsec/isva"
                  template_name: ""
                  company_name: "CIC"
                  decrypt_keystore: "rt_profile_keys"
                  decrypt_key_label: "runtime"
                  signing_keystore: "rt_profile_keys"
                  signing_key_label: "runtime"
                  validate_authn_request: true
                  sso_service_binding: "post"
                  active_delegate_id: "skip-identity-map"
                  need_consent_to_federate: false
                  message_issuer_format: ""
                  partners:
                  - name: "securitypoc.ice.ibmcloud.com"
                    role: "sp"
                    enabled: true
                    acs:
                    - binding: "post"
                      default: false
                      index: "1"
                      url: "https://securitypoc.ice.ibmcloud.com/saml/sps/saml20sp/saml20/login"
                    - binding: "redirect"
                      default: false
                      index: "2"
                      url: "https://securitypoc.ice.ibmcloud.com/saml/sps/saml20sp/saml20/login"
                    single_logout_service:
                    - binding: "post"
                      url: "https://securitypoc.ice.ibmcloud.com/saml/sps/saml20sp/saml20/slo"
                    - binding: "redirect"
                      url: "https://securitypoc.ice.ibmcloud.com/saml/sps/saml20sp/saml20/slo"
                    validate:
                      authn_request: true
                      logout_request: true
                      logout_response: false
                      keystore: "rt_profile_keys"
                      key_label: "validation-encryption-1501211921641.cer"
                    encryption:
                      keystore: "rt_profile_keys"
                      key_label: "validation-encryption-1501211921641.cer"
                      block_encryption_algorithm: "AES-128"
                      key_transport_algorithm: "RSA-OAEP"
                    provider_id: "https://securitypoc.ice.ibmcloud.com/saml/sps/saml20sp/saml20"
                    signature_algorithm: "RSA-SHA1"
                    signature_digest_algorithm: "SHA1"
                  reverse_proxy: "default-proxy"
                - name: "OIDCRP-IBMid"
                  protocol: "OIDCRP"
                  redirect_uri_prefix: "https://login.ibm.com/oidc"
                  response_types:
                  - "code"
                  active_delegate_id: "default-map"
                  mapping_rule: "mapping/rules/federations/verify_ibm_id.js"
                  advanced_configuration_active_delegate: "default-map"
                  advanced_configuration_mapping_rule: "mapping/rules/federations/verify_ibm_id_adv.js"
                  partners:
                  - name: "IBMid-AuthorizationCode"
                    enabled: true
                    client_id: !secret default/isva-secrets:ibmid_client_id
                    client_secret: !secret default/isva-secrets:ibmid_client_secret
                    metadata_endpoint: "https://login.ibm.com/oidc/endpoint/default/.well-known/openid-configuration"
                    scope:
                    - "openid"
                    token_endpoint_auth_method: "client_secret_post"
                    signing_algorithm: "RS256i"
                  reverse_proxy: "default-proxy"


Point Of Contact
================
The point of contact profile is used to control how the runtime server communicates with the point of contact server (usually WebSEAL).


.. autoclass:: src.verify_access_autoconf.federation.FED_Configurator.Point_Of_Contact_Profiles
   :members:


Alias Service
=============
The alias service stores and retrieves aliases that are related to a federated identity. Persistent name identifier format allows 
you to link a user at the identity provider with a user at the service provider. Verify Access stores these account linkages in 
a high-volume database or an LDAP database. 


.. autoclass:: src.verify_access_autoconf.federation.FED_Configurator.Alias_Service
   :members:


Attribute Sources
=================
Identity attribute sources for federated identities.


.. autoclass:: src.verify_access_autoconf.federation.FED_Configurator.Attribute_Sources
    :members:


Access Policies
===============
Access policies can be applied to the deployment types:
- SAML 2.0 identity provider federation
- SAML 2.0 service provider partner to an identity provider federation
- OpenID Connect and API Protection Definition


.. autoclass:: src.verify_access_autoconf.federation.FED_Configurator.Access_Policies
    :members:



Security Token Service
======================


.. autoclass:: src.verify_access_autoconf.federation.FED_Configurator.Security_Token_Service
    :members:


Federations
===========


.. autoclass:: src.verify_access_autoconf.federation.FED_Configurator.Federations
    :members:

.. autoclass:: src.verify_access_autoconf.federation.Federation_Common
    :members: