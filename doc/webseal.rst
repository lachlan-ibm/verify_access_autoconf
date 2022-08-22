
Example
=======


.. _webseal::

WebSEAL module configuration
============================
This section covers the WebSEAL configuration of a Verify Access deployment. This includes configuring the reverse proxy
policy server and user registry.


Administrators can also use this section to cover WebSEAL specific functionality such as HTTP transformation rules, 
client certificate mapping, federated user registries.


.. _webseal_runtime_component::

Runtime component
^^^^^^^^^^^^^^^^^
The WebSEAL runtime server is the Directory Server which contains the reverse proxy's user registry and policy server. 
This is typically a LDAP server external to the deployment, however an example LDAP server is made available to 
deployments for testing.

The Verify Access specific LDAP schemas can be found in the System -> File Downloads section of an appliance/configuration
container in the ``isva`` directory.

Any PKI required to verify this connection should be imported into a SSL database before the runtime component is 
configured.

An example runtime configuration is:

.. code-block:: yaml
   runtime:
     policy_server: "remote"
     user_registry: "remote"
     ldap:
       host: "openldap"
       port: 636
       dn: "cn=root,secAuthority=Default"
       dn_password: @secrets/isva-secrets:ldap-passwd
       key_file: "lmi_trust_store"
     clean_ldap: True
     domain: "Default"
     admin_user: "sec_master"
     admin_password: @secrets/isva-secrets:secmaster-passwd
     admin_cert_lifetime: 1460
     ssl_compliance: "FIPS 140-2"


.. _webseal_reverse_proxy::

Reverse Proxy
^^^^^^^^^^^^^
The WebSEAL reverse proxy configuration creates reverse proxy instances and associated configurations. This option can 
be used to create one or more reverse proxy instances along with associated backend server and authentication 
configuration. A complete list of the available configuration properties can be found 
`here <https://ibm-security.github.io/pyisva>`_. An example configuration is:

.. code-block:: yaml
  reverse_proxy:
  - name: "default"
    hostname: "hostname"
    address: "0.0.0.0"
    listening_port: 7234
    domain: "Default"
    http: 
    - enabled: "no"
    https:
    - enabled: "yes"
      port: 443
    junctions:
    - name: "/app"
      transparent_path: True
      server:
        host: "1.2.3.4"
        port: 443
      ssl:
      - enabled: "yes"
        key_file: "example.kdb",
        cert_file: "server"
    aac_configuration_wizard:
      hostname: "localhost"
      port: 443
      user: "easuser"
      password: "password"
      junction: "/mga"
      reuse_acls: True
      reuse_certs: True


.. _webseal_client_cert_map::

Client certificate mapping
^^^^^^^^^^^^^^^^^^^^^^^^^^
Client certificate mapping can be used by a reverse proxy to map X500 Name attribute from a client certificate (part of 
a mutual TLS connection) to authenticate a user as an identity from the User Registry. These mapping rules are written 
in XSLT. A rule is read from a file and uploaded to an appliance, where the resulting rule name is the filename minus the 
XSLT extension. A complete list of the available configuration properties can be found `here <https://ibm-security.github.io/pyisva>`_. 
An example configuration is:


.. code-block:: yaml
   client_cert_mapping:
   - demo.mapping.xslt
   - cert_to_uid.xlst


.. _webseal_jct_mapping::

Junction Mapping
^^^^^^^^^^^^^^^^
A Junction mapping table maps specific target resources to junction names. Junction mapping is an alternative to 
cookie-based solutions for filtering dynamically generated server-relative URLs. A rule is read from a file and uploaded 
to a Verify Access deployment. The name of the file which contains the junction mapping config is the resulting rule name
in Verify Access. An example configuration is:

.. code-block:: yaml
   junction_mapping:
   - demo.jct.map
   - another.jct.map


.. _webseal_url_mapping::

URL Mapping
^^^^^^^^^^^
A URL mapping table is used to map WebSEAL access control lists (ACLs) and protected object policies (POPs) to dynamically
generated URLs, such as URLs with query string parameters. URLs can be matched using a subset of UNIX shell pattern 
matching (including wildcards). A complete list of supported regex can be found `here <https://www.ibm.com/docs/en/sva/latest?topic=configuration-supported-wildcard-pattern-matching-characters#ref_wildcard_sup>`_
An example URL mapping configuration is:

.. code-block:: yaml
   url_mapping:
   - dyn.url.conf
   - url.map.conf


.. _webseal_user_mapping::

User Mapping
^^^^^^^^^^^^
User mapping can be used to modify or enrich an authenticated user's credential data. This can be used to both switch the 
identity of a user or add attributes to a user's existing credential. User mapping rules are added to a Verify Access 
deployment using XLST rules. Detailed information about user mapping XSLT configuration can be found `here <https://www.ibm.com/docs/en/sva/latest?topic=methods-authenticated-user-mapping>`_. The name of the XSLT file will be used as the name of the user mapping rule

.. code-block:: yaml
   user_mapping:
   - add_email.xslt
   - federated_identity_to_basic_user.xslt


.. _webseal_fsso::

Forms Based Single Sign-On
^^^^^^^^^^^^^^^^^^^^^^^^^^
The FSSO (forms single sing-on) module can be used by WebSEAL to authenticate a user to a junctioned application server. 
The module is capable of intercepting authentication requests from an application server, and then supplying the required 
identity information (retrieved from either the WebSEAl user regitry or a HTTP service) to the application server to complete 
the authentication challenge. More detailed information about FSSO concepts can be found `here <https://www.ibm.com/docs/en/sva/latest?topic=solutions-forms-single-sign-concepts>`_. The name of the FSSO configuration file will be used as the name of the resulting FSSO configuration in 
Verify Access. An example FSSO configuration is:


.. code-block:: yaml
   fsso:
   - liberty_jsp_fsso.conf
   - fsso.conf


.. _webseeal_http_transformations::

HTTP Transformation Rules
^^^^^^^^^^^^^^^^^^^^^^^^^
HTTP transformation rules allow WebSEAL to inspect and rewrite request and response objects as they pass through the 
reverse proxy. HTTP transforms can be applied: when the request is recieved (by WebSEAL); after an authorization decision has been 
made; and when the response is recieved (by WebSEAL). Prior to Verify Access 10.0.4.0 only XSLT rules were supported, 
from 10.0.4.0 onwards, LUA scripts can also be used to write HTTP transforms. Detailed information about HTTP 
transformation concepts can be found `here <https://www.ibm.com/docs/en/sva/latest?topic=junctions-http-transformations>`_. 
The name of the HTTP transform file will be used as the name of the resulting HTTP transformation rule in Verify Access. 
An example HTTP transformation configuration is:

.. code-block:: yaml
   http_transforms:
   - inject_header.xslt
   - eai.lua


.. _webseal_kerberos::

Kerberos
^^^^^^^^
The SPNEGO/Kerberos module can be used to enable SSO solutuions to Microsoft (Active Directory) systems via Kerberos 
delegation. Kerberos is configured by setting properties by id and subsections. There are several top level id's which 
can be used to configure Kerberos Realms, Local Domain Realms, Certificate Authority paths and Keyfiles. An example 
configuration is:

.. code-block:: yaml
   kerberos:
     libdefault:
       default_realm: "test.com"
     realms:
     - name: "test.com"
       properties:
       - kdc: "test.com"
     domain_realms:
     - name: "demo.com"
       dns: "test.com"
     keytabs:
     - admin.keytab
     - user.keytab


.. _webseal_pwd_strength::

Password Strength Rules
^^^^^^^^^^^^^^^^^^^^^^^
The password strength  module can be used to enforce XLST defined password requirements for basic and full Verify Access 
users. More detailed information about rule syntax can be found `here <https://www.ibm.com/docs/en/sva/latest?topic=methods-password-strength>`_. 
Rules are uploaded to a deployment from files, the name of the file is used as the resulting password strength rule in 
Verify Access. An example configuration is:

.. code-blaock:: yaml
   password_strength:
   - demo_rule.xlst


.. _webseal_rsa_config::

RSA SecurID Authenticaton
^^^^^^^^^^^^^^^^^^^^^^^^^
The RSA integration module can be used to allow users who are authenticating to WebSEAL's user registry to use a RSA OTP 
as a second factor. More information about configuring this mechanism and the correcsponding configuration to integrate 
with WebSEAL login can be found `here <https://www.ibm.com/docs/en/sva/latest?topic=methods-token-authentication>`_. An 
example configuration is:

.. code-block:: yaml
   rsa_config:
     server_config: server.conf
     optional_server_config: optional_server.conf


.. _webseal_runtime_server

Runtime Component
^^^^^^^^^^^^^^^^^
The runtime configuration defines the runtime policy server and user registry used by WebSEAL. This is typically a Directory 
server and one is providede by Verify Access for testing and demonstration purposes. A detailed list of all of the avaliable 
configuration properties can be found `here <https://ibm-security.github.io/pyisva>`_. An example configuration is:

.. code-block:: yaml
   runtime:
     policy_server: "remote"
     user_registry: "remote"
     domain: "Default"
     admin_password:
     ldap:
       host: "openldap"
       port: 636
       dn: "cn=root,secAuthority=Default"
       dn_password: @secrets/isva-secrets:ldap-pwd
       key_file: lmi_trust_store.p12
     admin_cert_lifetime: 1460
     ssl_complaince: FIPS 140-2


.. _webseal_reverse_proxy

Reverse Proxy Instances
^^^^^^^^^^^^^^^^^^^^^^^
WebSEAL reverse proxy instances form the core of most Verify Access deployments. There are a large number of configuration 
options which can be specified for this section. A reverse proxy isntance typically defines one or more junctions to 
protected application servers. This section can also be used to define configuration for the ``webseal.conf`` file as well 
as run the integration wizards for MMFA, AAC and Federation capabilities from the Federated Runtime Server. A detailed 
list of all of the avaliable configuration properties can be found `here <https://ibm-security.github.io/pyisva>`_. 
An example configuration is:

.. code-block:: yaml
   reverse_proxy:
     - name: "default-proxy"
       listening_port: 7234
       domain: "Default"
       ldap:
         ssl_yn: "no"
       http:
         enable: "no"
       https:
         enable: "yes"
         port: 9443
       nw_interface_yn: "yes"
       stanza_configuration:
         - stanza: "junction"
           entry_name: "macro"
           value: "*JSESS*, *VCAP*, *WAS*, PD_STATEFUL*"
           operation: "add"
         - stanza: "session"
           entry_name: "timeout"
           value: "28800"
           operation: "update"
         - stanza: "session"
           entry_name: "inactive-timeout"
           value: "28800"
           operation: "update"
         - stanza: "local-response-macros"
           entry_name: "macro"
           value: "URL:requestURL"
           operation: "add"
         - stanza: "local-response-macros"
           entry_name: "macro"
           value: "URL:requestURL"
           operation: "add"
         - stanza: "local-response-macros"
           entry_name: "macro"
           value: "REFERER:referer"
           operation: "add"
         - stanza: "eai"
           entry_name: "eai-auth"
           value: "https"
           operation: "update"
         - stanza: "oauth"
           entry_name: "oauth-auth"
           value: "https"
           operation: "update"
         - stanza: "ba"
           entry_name: "ba-auth"
           value: "https"
           operation: "update"
         - stanza: "acnt-mgt"
           entry_name: "single-signoff-uri"
           operation: "delete"
         - stanza: "acnt-mgt"
           entry_name: "enable-local-response-redirect"
           value: "yes"
           operation: "update"
         - stanza: "local-response-redirect"
           entry_name: "local-response-redirect-uri"
           value: "[login] /home"
           operation: "add"
       junctions:
         - junction_point: "/home"
           server_hostname: demo.application
           server_port: 9080
           remote_http_header:
             - "iv-user"
             - "iv-creds"
           request_encoding: "utf8_uri"
           junction_type: "tcp"
           transparent_path_junction: "yes"
           scripting_support: "no"
         - junction_point: "/static"
           server_hostname: resource.server
           server_port: 9080
           remote_http_header:
             - "iv-user"
             - "iv-creds"
           request_encoding: "utf8_uri"
           junction_type: "tcp"
           transparent_path_junction: "yes"
           scripting_support: "no"
         - junction_point: "/protected"
           server_hostname: protected.application
           server_port: 9443
           remote_http_header:
             - "iv-user"
             - "iv-creds"
           request_encoding: "utf8_uri"
           junction_type: "ssl"
           transparent_path_junction: "yes"
           scripting_support: "no"
         - junction_point: "/accounts"
           server_hostname: protected.application
           server_port: 9443
           remote_http_header:
             - "iv-user"
             - "iv-creds"
           request_encoding: "utf8_uri"
           junction_type: "ssl"
           transparent_path_junction: "yes"
           scripting_support: "no"
         - junction_point: "/scim"
           server_hostname: isvaruntime
           server_port: 9443
           remote_http_header:
             - "iv-user"
             - "iv-groups"
             - "iv-creds"
           request_encoding: "utf8_uri"
           junction_cookie_javascript_block: "inhead"
           junction_type: "ssl"
           transparent_path_junction: "yes"
           scripting_support: "yes"
           client_ip_http: "yes"
           username: "easuser"
           password: @secrets/isva-secrets/runtime_password
           enable_basic_auth: true
         - junction_point: "/intent"
           server_hostname: protected.application.server
           server_port: 9443
           remote_http_header:
             - "iv-user"
             - "iv-creds"
           request_encoding: "utf8_uri"
           junction_type: "ssl"
           transparent_path_junction: "no"
           scription_support: "no"
         - junction_point: "/ob"
           server_hostname: application.server
           server_port: 9080
           remote_http_header:
             - "iv-user"
             - "iv-groups"
             - "iv-creds"
           request_encoding: "utf8_uri"
           junction_cookie_javascript_block: "inhead"
           junction_type: "ssl"
           transparent_path_junction: "no"
           scripting_support: "yes"
           client_ip_http: "yes"
           username: "application_user"
           password: @secrets/isva-secrets/app_pwd
           enable_basic_auth: true
       mmfa_configuration:
         lmi:
           hostname: isvaconfig
           port: 443
           user: admin
           password: @secrets/isva-secrets:admin_pwd
         runtime:
           hostname: isvaruntime
           port: #TODO
           user: #TODO
           password: #TODO
         channel: "browser"
         reuse_acls: true
         reuse_pops: true
         reuse_certs: true
       aac_configuration:
         hostname: #TODO
         port: 443
         junction: "/mga"
         user: "easuser"
         password: @secrets/isva-secrets:runtime_pwd
         reuse_acls: true
         reuse_certs: true
     - name: "verify_mobile"
       listening_port: 7235
       domain: "Default"
       ldap:
         ssl_yn: "yes"
         port: 636
       http:
         enabled: "no"
       https:
         enabled: "yes"
         port: 9443
       junctions:
         - junction_point: "/scim"
           server_hostname: isvaruntime
           server_port: 443
           remote_http_header:
             - "iv-user"
             - "iv-groups"
             - "iv-creds"
           request_encoding: "utf8_uri"
           junction_cookie_javascript_block: "inhead"
           junction_type: "ssl"
           transarent_path_junction: "yes"
           scripting_support: "yes"
           scient_ip_http: "yes"
           username: "easuser"
           password: @secrets/isva-secrets:runtime_pwd
           enable_basic_auth: true
       mmfa_cofiguration:
         lmi:
           hostname: isvaconfig
           port: 443
           user: admin
           password: @secrts/isva-secrets:admin_pwd
         runtime:
           hostname: "isvaruntime"
           port: 443
           user: "easuser"
           password: @secrts/isva-secrets:runtime_pwd
         channel: "mobile"
         reuse_acls: true
         reuse_pops: true
         reuse_certs: true

