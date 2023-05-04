WebSEAL Reverse Proxy Configuration
###################################
This section covers the WebSEAL configuration of a Verify Access deployment. This includes configuring the reverse proxy
policy server and user registry.

Administrators can also use this section to cover WebSEAL specific functionality such as HTTP transformation rules, 
client certificate mapping, federated user registries.


Example
=======

.. code-block:: yaml

                webseal:
                  runtime:
                    policy_server: "ldap"
                    user_registry: "ldap"
                    ldap:
                      host: "openldap"
                      port: 636
                      dn: "cn=root,secAuthority=Default"
                      dn_password: "Passw0rd"
                      key_file: "lmi_trust_store"
                    clean_ldap: True
                    domain: "Default"
                    admin_user: "sec_master"
                    admin_password: "Passw0rd"
                    admin_cert_lifetime: 1460
                    ssl_compliance: "fips"
                  reverse_proxy:
                  - name: "default"
                    host: "isvaruntime"
                    http:
                      enabled: "no"
                    https:
                      enabled: "yes"
                    domain: "Default"
                    ldap:
                      ssl_yn: "yes"
                      port: 636
                      key_file: "lmi_trust_store"
                    aac_configuration:
                      hostname: "isvaruntime"
                      port: 9443
                      junction: "/mga"
                      user: "easuser"
                      password: "passw0rd"
                      reuse_certs: True
                      reuse_acls: True
                    stanza_configuration:
                    - stanza: "acnt-mgt"
                      entry_id: "enable-local-response-redirect"
                      value: "yes"
                      operation: "update"
                    - stanza: "local-response-redirect"
                      entry_id: "local-response-redirect-uri"
                      value: "/mga/sps/authsvc?PolicyId=urn:ibm:security:authentication:asf:password"
                      operation: "update"
                  pdadmin:
                    users:
                    - name: "testuser"
                      dn: "cn=testuser,dc=ibm,dc=com"
                      password: "passw0rd"


.. _webseal_reverse_proxy:

Reverse Proxy Instances
=======================
Properties to configure a WebSEAL Reverse Proxy instance. A reverse proxy instance typically defines one or more junctions to 
protected application servers. This section can also be used to define configuration for the ``webseal.conf`` file as well 
as run the integration wizards for MMFA, AAC and Federation capabilities from the Federated Runtime Server. 

Stanza configuration
____________________
For each WebSEAL reverse proxy instance, administrators are able to define section/key/value entries to modify the 
``webseal.conf`` file for that instance. Each stanza modification must also include an operation to either: add an 
entry, creating duplicate entries if the particular section/key combination already exists; update an entry if it already 
exists, or add it if it does not; and remove an entry if it exists.


Junction configuration
______________________
For each WebSEAL instance, administrators will typically define one or more standard or virtual junctions. Junctions are 
how an administrator defines the relationship and behavior between a WebSEAL server and an application server (for whom 
TCP traffic is being proxied by WebSEAL). Some advanced configuratioin options cannot be set in this entry and the Stanza 
configuration must be used to set key/value entries in the reverse proxy config file.


.. autoclass:: src.verify_access_autoconf.webseal.WEB_Configurator.Reverse_Proxy
   :members:


.. _pdadmin:

Policy Directory Admin
======================
Administrators can also use the ``pdadmin`` tool to modify the configured User Registry and Policy Server. This tool is
used to: create Access Control Lists (ACL's); create Proteced Object Policies (POP's); create users or groups; as well 
as attaching ACL's or POP's to a reverse proxy instance's object space.


.. autoclass:: src.verify_access_autoconf.webseal.WEB_Configurator.PD_Admin
   :members:


.. _webseal_client_cert_map:

Client certificate mapping
==========================
Client certificate mapping can be used by a reverse proxy to map X500 Name attribute from a client certificate (part of 
a mutual TLS connection) to authenticate a user as an identity from the User Registry. These mapping rules are written 
in XSLT. A rule is read from a file and uploaded to an appliance, where the resulting rule name is the filename minus the 
XSLT extension. A complete list of the available configuration properties can be found `here <https://ibm-security.github.io/pyisva>`_. 
An example configuration is:


.. autoclass:: src.verify_access_autoconf.webseal.WEB_Configurator.Client_Certificate_Mapping
   :members:


.. _webseal_jct_mapping:

Junction Mapping
================
A Junction mapping table maps specific target resources to junction names. Junction mapping is an alternative to 
cookie-based solutions for filtering dynamically generated server-relative URLs. A rule is read from a file and uploaded 
to a Verify Access deployment. The name of the file which contains the junction mapping config is the resulting rule name
in Verify Access. An example configuration is:


.. autoclass:: src.verify_access_autoconf.webseal.WEB_Configurator.Junction_Mapping
   :members:


.. _webseal_url_mapping:

URL Mapping
===========
A URL mapping table is used to map WebSEAL access control lists (ACLs) and protected object policies (POPs) to dynamically
generated URLs, such as URLs with query string parameters. URLs can be matched using a subset of UNIX shell pattern 
matching (including wildcards). A complete list of supported regex can be found `here <https://www.ibm.com/docs/en/sva/latest?topic=configuration-supported-wildcard-pattern-matching-characters#ref_wildcard_sup>`_


.. autoclass:: src.verify_access_autoconf.webseal.WEB_Configurator.Url_Mapping
   :members:


.. _webseal_user_mapping:

User Mapping
============
User mapping can be used to modify or enrich an authenticated user's credential data. This can be used to both switch the 
identity of a user or add attributes to a user's existing credential. User mapping rules are added to a Verify Access 
deployment using XLST rules. Detailed information about user mapping XSLT configuration can be found `here <https://www.ibm.com/docs/en/sva/latest?topic=methods-authenticated-user-mapping>`_. 
The name of the XSLT file will be used as the name of the user mapping rule.


.. autoclass:: src.verify_access_autoconf.webseal.WEB_Configurator.User_Mapping
   :members:


.. _webseal_fsso:

Forms Based Single Sign-On
==========================
The FSSO (forms single sing-on) module can be used by WebSEAL to authenticate a user to a junctioned application server. 
The module is capable of intercepting authentication requests from an application server, and then supplying the required 
identity information (retrieved from either the WebSEAl user registry or a HTTP service) to the application server to complete 
the authentication challenge. More detailed information about FSSO concepts can be found `here <https://www.ibm.com/docs/en/sva/latest?topic=solutions-forms-single-sign-concepts>`_. 
The name of the FSSO configuration file will be used as the name of the resulting FSSO configuration in Verify Access.


.. autoclass:: src.verify_access_autoconf.webseal.WEB_Configurator.Form_Single_Sign_On
   :members:


.. _webseal_http_transformations:

HTTP Transformation Rules
=========================
HTTP transformation rules allow WebSEAL to inspect and rewrite request and response objects as they pass through the 
reverse proxy. HTTP transforms can be applied: when the request is received (by WebSEAL); after an authorization decision has been 
made; and when the response is received (by WebSEAL). Prior to Verify Access 10.0.4.0 only XSLT rules were supported, 
from 10.0.4.0 onwards, LUA scripts can also be used to write HTTP transforms. Detailed information about HTTP 
transformation concepts can be found `here <https://www.ibm.com/docs/en/sva/latest?topic=junctions-http-transformations>`_. 
The name of the HTTP transform file will be used as the name of the resulting HTTP transformation rule in Verify Access. 


.. autoclass:: src.verify_access_autoconf.webseal.WEB_Configurator.Http_Transformations
   :members:


.. _webseal_kerberos:

Kerberos
========
The SPNEGO/Kerberos module can be used to enable SSO solutions to Microsoft (Active Directory) systems via Kerberos 
delegation. Kerberos is configured by setting properties by id and subsections. There are several top level id's which 
can be used to configure Kerberos Realms, Local Domain Realms, Certificate Authority paths and key files. An example 
configuration is:


.. autoclass:: src.verify_access_autoconf.webseal.WEB_Configurator.Kerberos
   :members:


.. _webseal_pwd_strength:

Password Strength Rules
=======================
The password strength  module can be used to enforce XLST defined password requirements for basic and full Verify Access 
users. More detailed information about rule syntax can be found `here <https://www.ibm.com/docs/en/sva/latest?topic=methods-password-strength>`_. 
Rules are uploaded to a deployment from files, the name of the file is used as the resulting password strength rule in 
Verify Access. An example configuration is:


.. autoclass:: src.verify_access_autoconf.webseal.WEB_Configurator.Password_Strength


.. _webseal_rsa_config:

RSA SecurID Authenticaton
=========================
The RSA integration module can be used to allow users who are authenticating to WebSEAL's user registry to use a RSA OTP 
as a second factor. More information about configuring this mechanism and the correcsponding configuration to integrate 
with WebSEAL login can be found `here <https://www.ibm.com/docs/en/sva/latest?topic=methods-token-authentication>`_. An 
example configuration is:


.. autoclass:: src.verify_access_autoconf.webseal.WEB_Configurator.RSA
   :members:

.. _webseal_runtime_server:

Runtime Component
=================
The WebSEAL runtime server is the Directory Server which contains the reverse proxy's user registry and policy server. 
This is typically a LDAP server external to the deployment, however an example LDAP server is made available to 
deployments for testing.

The Verify Access specific LDAP schemas can be found in the System -> File Downloads section of an appliance/configuration
container in the ``isva`` directory.

Any PKI required to verify this connection should be imported into a SSL database before the runtime component is 
configured.


.. autoclass:: src.verify_access_autoconf.webseal.WEB_Configurator.Runtime
   :members:


API Access Control
==================
Properties to configure an API Authorization Server. An API authorization server typically defines one or more resource 
servers which have authentication requirements to permit access. This section can also be used to configure Cross-Origin 
Resource Sharing (CORS) policies.

Authorization Server
____________________
Authorization servers are the points of contact for external traffic to access protected resource servers. Each server 
has its own object space in the Verify Access policy server.

Resource Servers
________________
Resource servers are third party application servers / microservices that are being protected by the Authorization 
server.

Document Root
_____________
The document root defines a static set of web files (HTML, JS, CSS, ect.) which can be served by the Authorization
server.

Cross-Origin Resource Sharing
_____________________________
The CORS properties can be used to configure the URI's which are permitted to make cross-origin resource requests as 
well as the types of resources which are permitted to be shared.


.. autoclass:: src.verify_access_autoconf.webseal.WEB_Configurator.Api_Access_Control
   :members:
