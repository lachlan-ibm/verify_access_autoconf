Advanced Access Control Configuration
#####################################

This configuration module is used to apply configuration to the runtime Liberty server. This includes configuring the 
runtime authorization server, context-based access, SCIM, FIDO2, Authentication, risk-based access and MMFA.


Example
=======

.. code-block:: yaml

                  access_control:
                     authentication:
                        policies:
                        - name: "Username Passwword"
                           description: "Username and password authentication policy."
                           enabled: true
                           uri: "urn:ibm:security:authentication:asf:password"
                           policy: "<Policy xmlns=\"urn:ibm:security:authentication:policy:1.0:schema\" PolicyId=\"urn:ibm:security:authentication:asf:password\"><Description>Username and password authentication policy.</Description><Step type=\"Authenticator\"><Authenticator AuthenticatorId=\"urn:ibm:security:authentication:asf:mechanism:password\"/></Step><Actions><Action On=\"null\" type=\"null\"><AttributeAssignments/></Action></Actions></Policy>"
                        mechanisms:
                        - name: "Username Passowrd"
                          type: "Username Password"
                          description: "Username password authentication"
                          uri: "urn:ibm:security:authentication:asf:mechanism:password"
                          properties:
                          - usernamePasswordAuthentication.enableLastLogin: "false"
                          - usernamePasswordAuthentication.loginFailuresPersistent: "false"
                          - usernamePasswordAuthentication.maxServerConnections: "16"
                          - usernamePasswordAuthentication.mgmtDomain: "Default"
                          - usernamePasswordAuthentication.sslServerStartTLS: "false"
                          - usernamePasswordAuthentication.useFederatedDirectoriesConfig: "false"
                          - usernamePasswordAuthentication.userSearchFilter: "(|(objectclass=ePerson)(objectclass=Person))"
                          - usernamePasswordAuthentication.ldapBindDN: "cn=root,secAuthority=Default"
                          - usernamePasswordAuthentication.ldapHostName: "openldap"
                          - usernamePasswordAuthentication.ldapBindPwd: "Passw0rd"
                          - usernamePasswordAuthentication.ldapPort: "636"
                          - usernamePasswordAuthentication.sslEnabled: "true"
                          - usernamePasswordAuthentication.sslTrustStore: "lmi_trust_store"
                          attributes:
                          - selector: "mobile"
                            name: "mobileNumber"
                            namespace: "urn:ibm:security:authentication:asf:mechanism:password"
                          - selector: "mail"
                            name: "emailAddress"
                            namespace: "urn:ibm:security:authentication:asf:mechanism:password"


.. _api_protection::

API Protection
==============
OIDC API portection configuration for definitions and clients. This is capable of creating OpenBanking and FAPI compliant
defintions and clients.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.API_Protection
   :members:


.. _authentication::

Authenticaton
=============
This section desribes how to create authentication policies and mechanisms. Authentication policies can be used in 
risk-based access or context-based access policies to conditionally enforce additional authentication/authorization 
requirements.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Authentication
   :members:


.. _access_control::

Context Based Access Control
============================
This section covers the configuration of the Context Based Access policy engine of a Verify Access deployment. 


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Access_Control
   :members:


Risk Based Access Control
=========================
TODO


.. _access_control_template_file::

HTTP Template Files
===================
This configuration option can be used to set files or directories containing HTML files which are compatible with the 
AAC and Federation templating engine. The directory structure of any directories to upload should follow the default 
top level directories. If you are defining a direcotyr it should contian a trailing ``/``. An example configuration is:


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Template_Files
   :members:


.. _access_control_mapping_rule::

JavaScript Mapping Rules
========================
This configuration option can be used to upload different types or categories of JavaScript Mapping Rules. These rules 
are typically used to implement custom buisness logic for a particular integration requirement. The types of mapping rules
supported are:
#TODO

.. note:: Some types of mapping rules are defined elsewhere, eg OIDC pre/post token mapping rules must be defined with 
          the OIDC definition they are associated with.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Mapping_Rules
   :members:


.. _access_control_push_notification::

Push Notification Service
=========================
This configuration option can be sued to integrate with Apple/Google mobile push notification service.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Push_Notification_Provider
   :members:


Mobile Multi-Factor Authentication
==================================
Configure MMFA capabilities.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Mobile_Multi_Factor_Authentication
   :members:


.. _access_control_server_connections::

Server Connections
==================
Server connections are used to connect to third party infrastructure such as LDAP registries, email servers, SMS servers, ect.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Server_Connections
   :members:


Advanced Configuration Parameters
=================================


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Advanced_Configuration
   :members:


SCIM
====

.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.System_CrossDomain_Identity_Management
   :members: