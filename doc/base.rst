.. _base-module::

Base Module
-----------
The base configurator is responsible for completing the first steps (SLA), activating licensed modules, importing 
PKI and system wide settings like date/time/networking.

The example yaml snippets below can be used as a template to build your configuration file.

Features
--------

.. _sla-first-steps::

SLA / First steps
^^^^^^^^^^^^^^^^^
The configurator can be used to accept the Service License Agreement as well as the "first steps" LMI prompts, including 
enabling FIPS compliance. This is always done with the admin account using the default password.
Failing this step does not result in the autoconfig aborting.


.. _lmi-password-update::

Password update
^^^^^^^^^^^^^^^
The password of the management account may be updated once. This account must already exist on the appliance and
have sufficient permission to complete all of the configuration required.


.. code-block:: yaml
  mgmg_base_url: 'https://isva.mgmt.lmi'
  mgmt_password: 'Passw0rd'
  mgmt_old_password: 'admin'


.. _system-settings::

System settings
^^^^^^^^^^^^^^^
System wide settings such as LMI log file configuration, account management and advanced tuning parameters.


.. code-block:: yaml
lmi: #Local Management Interface settings
  timeout: 720
  timezone: "Australia/Brisbane"


.. _ssl-database::

SSL Certificate database
^^^^^^^^^^^^^^^^^^^^^^^^
X509 Certificates and PCKS12 key-files can be imported into Verify Access SSL databases. The structure of this 
configuration option is to specify a yaml list of SSL databases. Each entry in the list has three keys: database name; 
personal certificates; and signer certificates. If a database does not exist on the appliance then it is created before 
files are imported.

SSL certificates are imported into the appliance by reading files from the file system. Therefore any PKI which is to 
be imported into the appliance must specify the fully-qualified path or be a path relative to the ``ISVA_CONFIG_BASE`` 
environment variable.


.. code-block:: yaml
  ssl_certificates:
    - database: "lmi_trust_store"
      personal_certificates:
        - "ssl/lmi_trust_store/personal"
      signer_certificates:
        - "ssl/lmi_trust_store/signer"
    - database: "rt_profile_keys"
      signer_certificates:
        - "ssl/rt_profile_keys/signer"


.. _cluster-configuration::

Cluster Configuration
^^^^^^^^^^^^^^^^^^^^^
The cluster configuration options can be used to add additional servers to the Verify Access deployment. Currently only
 external databases (HVDB and config) as well as Verify Access HA servers are supported.

This option is typically used in a contianer deployment to configure the HVDB container.

.. note:: PKI required to connect to any servers should be imported in the previuos step.

.. code-block:: yaml
  cluster: #High Avaliablity/Extensal Services configuration
    config_database:
      address: "127.0.0.1"
      port: 1234
      username: "database_user"
      password: "database_password"
      ssl: True
      ssl_keystore: "lmi_trust_store.kdb"
      ssl_keyfile: "server.cer"



.. _module-activation::

Module Activation
^^^^^^^^^^^^^^^^^
License files to activate the Advanced Access Control, Federation and WebSEAL Reverse Proxy modules are imported in 
this step.


.. code-block:: yaml
  activation: #Activation codes
    base: "example"
    aac: "example"
    fed: "example"


.. _advanced-tuning-parameters::

Advanced tuning parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^
Advanced Tuning Parameters can be set on an appliance to configure additional settings not exposed by the LMI.

.. code-block:: yaml
  advanced_tuning_parameters:
    - wga.rte.embedded.ldap.ssl.port: 636


.. _deployment-specific-configuration::

Deployment specific configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Finally the base module will complete any deployment specific configuration.

Appliance:
In appliance deployments, administrators are able to configure the hostname, as well as network interfaces and routes 
for HTTP(S) traffic to the appliance. The :doc:`appliance` module contains the configuration options available to 
appliance deployments.

.. note:: Appliance deployments are defined by using the top level key "appliance" to define the :doc:`base-module`
        configuration.

Container:
In container deployments, administrators are able to configure the Management Authorization roles to enable an admin
defined service account to poll for configuration snapshots from a pre-defined service endpoint. The :doc:`container` 
module contains the container specific configuration options.

.. note:: Container deployments are defined by using the top level key "container" to define the :doc:`base-modul`
        configuration.

.. autoclass:: verify-access-configurator.configure
   :members:
