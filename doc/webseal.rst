
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
deployment using XLST rules. Detailed information about user mapping XSLT configuration can be found `here <https://www.ibm.com/docs/en/sva/10.0.4?topic=methods-authenticated-user-mapping>`_. The name of the XSLT file will be used as the name of the user mapping rule

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
the authentication challenge. More detailed information about FSSO concepts can be found `here <https://www.ibm.com/docs/en/sva/10.0.4?topic=solutions-forms-single-sign-concepts>`_. The name of the FSSO configuration file will be used as the name of the resulting FSSO configuration in 
Verify Access. An example FSSO configuration is:


.. code-block:: yaml
   fsso:
   - liberty_jsp_fsso.conf
   - fsso.conf



