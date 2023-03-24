Advanced Access Control Configuration
#####################################
This configuration module is used to apply configuration to the runtime Liberty server. This includes configuring the 
runtime authorization server, context-based access, SCIM, FIDO2, Authentication, Context-Based Access and MMFA.


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
Context based access policies are capable of definign conditional authentication requirements based on administrator
defined requirements (such as device registration status, ip reputation, authenciation method enrollment for a user).


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Access_Control
   :members:


Risk Profiles
=============
Risk profiles provide administrators with a mechanism to calcuate the "risk" of an authentication request
based on administrato-defined attributes. For example: creating a risk profile which examines the IPv4 
address of an incoming request to identify the location (continent, country, region, etc.) that the request
is coming from, and conditionaly enforcing addition authentication requirements for more "risky" requests.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Risk_Profiles
   :members:


Attributes
==========
Attributes allow an administrator to source information about a user from a number of different sources
to build up credential attributes, which can then be used by subsequent authentication/authorization flows.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Attributes
   :members:


Obligations
===========
Obligations are used to enforce buisness requirements (such as registering a device) during an authorization
flow before permitting access.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Obligations
   :members:


Policy Information Points
=========================
Policy Information Points allow administrators to integrate third party information sources to provide additional
context to an authorization policy before making a decision to permit/deny access.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Policy_Information_Points
   :members:


.. _access_control_template_file::

HTTP Template Files
===================
This configuration option can be used to set files or directories containing HTML files which are compatible with the 
AAC and Federation templating engine. The directory structure of any directories to upload should follow the default 
top level directories. If you are defining a directory it should contian a trailing ``/``.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Template_Files
   :members:


.. _access_control_mapping_rule::

JavaScript Mapping Rules
========================
This configuration option can be used to upload different types or categories of JavaScript Mapping Rules. These rules 
are typically used to implement custom buisness logic for a particular integration requirement.


.. note:: Some types of mapping rules are defined elsewhere, eg OIDC pre/post token mapping rules must be defined with 
          the OIDC definition they are associated with.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Mapping_Rules
   :members:


.. _access_control_push_notification::

Push Notification Service
=========================
This configuration option can be used to integrate with Apple/Google mobile push notification service.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Push_Notification_Provider
   :members:


Mobile Multi-Factor Authentication
==================================
Configure MMFA capabilities. These properties are used as a discovery mechanism for devices which have been
registered for a user; and is capable of initiating or completing an "out of band" authentication/authorization challenge.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Mobile_Multi_Factor_Authentication
   :members:


.. _access_control_server_connections::

Server Connections
==================
Server connections are used to connect to third party infrastructure such as LDAP registries, email servers, SMS servers, ect. These 
connections are used by other AAC components to provide authentication/authorization services.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Server_Connections
   :members:


Advanced Configuration Parameters
=================================
The Advanced Configuration Parameters entry is used to set module wide properties for authentication and authorization 
components. The list of avaliable properties is dependant on the target version of Verify Access beign configured. Administrators
are able to use the Verify Access assigned identifier or the name of the property.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Advanced_Configuration
   :members:


SCIM
====
This configuration property is used to configure Verify Access to integrate with either a LDAP server or a Verify Access User 
Registry (WebSEAL runtime component) using the System for Cross-Domain Identity Management interfaces. This allows 
administrators to create/manage users, as well as provide attributes to other Verify Access authentication components.

.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.System_CrossDomain_Identity_Management
   :members:


FIDO2
=====
The FIDO2 configuration property is used to create and manage FIDO2 relying parties and their associated verification
documents (metadata) as well as any custom logic applied in a JavaScript mediator.

.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Fast_Identity_Online2
   :members:


Runtime Server Configuration
============================
This property can be used to configure the runtime liberty server. This includes: configuring trace; managing endpoints/interfaces that
the runtime server can respond to requests; setting server configuration parameters (such as proxy settings, SSL configuration); and 
defining users in the runtime user registry.


.. autoclass:: src.verify_access_autoconf.access_control.AAC_Configurator.Runtime_Configuration
   :members: