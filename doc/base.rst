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


.. autofunction:: verify-access-autoconf.configure.ISVA_Configurator.accept_eula


.. autofunction:: verify-access-autoconf.configure.ISVA_Configurator.complete_setup


.. _lmi-password-update::

Password update
^^^^^^^^^^^^^^^
The password of the management account may be updated once. This account must already exist on the appliance and
have sufficient permission to complete all of the configuration required.


.. autofunction:: verify-access-autoconf.configure.ISVA_Configurator.set_admin_password


.. _system-settings::

System settings
^^^^^^^^^^^^^^^
System wide settings such as LMI log file configuration, account management and advanced tuning parameters.

To set system administrator settings use the ``admin_config`` key. A complete list of the available configuration 
properties can be found `here <https://ibm-security.github.io/pyisva>`_. An example configuration is:


.. autofunction:: verify-access-autoconf.configure.ISVA_Configurator.admin_config


.. _ssl-database::

SSL Certificate database
^^^^^^^^^^^^^^^^^^^^^^^^
X509 Certificates and PCKS12 key-files can be imported into Verify Access SSL databases. The structure of this 
configuration option is to specify a yaml list of SSL databases. Each entry in the list has three keys: database name; 
personal certificates; and signer certificates. If a database does not exist on the appliance then it is created before 
files are imported.

SSL certificates are imported into the appliance by reading files from the file system. Therefore any PKI which is to 
be imported into the appliance must specify the fully-qualified path or be a path relative to the ``ISVA_CONFIG_BASE`` 
environment variable. A complete list of the available configuration properties can be found 
`here <https://ibm-security.github.io/pyisva>`_. An example configuration is:


.. autofunction:: verify-access-autoconf.configure.ISVA_Configurator.import_ssl_certificates


Administrator Account Management
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Administrator accounts, groups and permissions for managing Verify Access features can be defined in two configuration
entries. The first entry allows for the creation of users and groups which can be used to authenticate to the 
management interface. A complete list of the available configuration properties can be found 
`here <https://ibm-security.github.io/pyisva>`_. An example configuration is:


.. autofunction:: verify-access-autoconf.configure.ISVA_Configurator.account_management


Administrators are also able to manage access to Verify Access features. This allows for more fine grained control 
over which accounts are permitted to modify a deployment. Administrators are not able to create new features, however 
they can create "roles" which contains permissions for one or more features. Each feature in a role has two permission
levels: read access (can view but cannot modify); and write access (permission to modify). A complete list of the 
available configuration properties can be found `here <https://ibm-security.github.io/pyisva>`_. An example 
configuration is:


.. autofunction:: verify-access-autoconf.configure.ISVA_Configurator.account_management


.. _cluster-configuration::

Cluster Configuration
^^^^^^^^^^^^^^^^^^^^^
The cluster configuration options can be used to add additional servers to the Verify Access deployment. Currently only
 external databases (HVDB and config) as well as Verify Access HA servers are supported.

This option is typically used in a container deployment to configure the HVDB container. A complete list of the available 
configuration properties can be found `here <https://ibm-security.github.io/pyisva>`_. An example configuration is:

.. note:: PKI required to connect to any servers should be imported in the previuos step.

.. code-block:: yaml
   config_db:
     address: "127.0.10.1"
     port: 1234
     username: "database_user"
     password: "database_password"
     ssl: True
     ssl_keystore: "lmi_trust_store.kdb"
     ssl_keyfile: "server.cer"
   runtime_db:
     address: "postgresql"
     port: 5432
     type: "Postgresql"
     user: "postgres"
     password: !secret verify-access/isva-secrets:postgres-passwd
     ssl: True
     db_name: "isva"
  cluster:
    sig_file: cluster/signature_file
    primary_master: "isva.primary.master"
    secondary_master: "isva.secondary.master"
    nodes:
    - "isva.node"
    resitrcted_nodes:
    - "isva.restricted.node"



.. _module-activation::

Module Activation
^^^^^^^^^^^^^^^^^
License files to activate the Advanced Access Control, Federation and WebSEAL Reverse Proxy modules are imported in 
this step. Subsequent module configuration is dependant on one or more of these licenses being applied to an appliance
or container. An example configuration is:


.. autofunction:: verify-access-autoconf.configure.ISVA_Configurator.activate_appliance


.. _advanced-tuning-parameters::

Advanced tuning parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^
Advanced Tuning Parameters can be set on an appliance to configure additional settings not exposed by the LMI. Any 
required advanced tuning parameters for your deployment will be communicated to you via support. An example 
configuration is:


.. autofunction:: verify-access-autoconf.configure.ISVA_Configurator.advanced_tuning_parameters


Configuration Snapshots
^^^^^^^^^^^^^^^^^^^^^^^
A snapshot can be applied to both Container and Appliance deployments to restore a previous configuration state. This 
is done via a signed archive file, generated by the deployment you are trying to preserve / re-create.


.. autofunction:: verify-access-autoconf.configure.ISVA_Configurator.apply_snapshot


.. _deployment-specific-configuration::

Deployment specific configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Finally the base module will complete any deployment specific configuration.

Appliance:
_________
In appliance deployments, administrators are able to configure the hostname, as well as network interfaces and routes 
for HTTP(S) traffic to the appliance. The :doc:`appliance` module contains the configuration options available to 
appliance deployments.

.. note:: Appliance deployments are defined by using the top level key "appliance" to define the :doc:`base-module`
        configuration.

Container:
__________
In container deployments, administrators are able to configure the Management Authorization roles to enable an admin
defined service account to poll for configuration snapshots from a pre-defined service endpoint. The :doc:`container` 
module contains the container specific configuration options.

.. note:: Container deployments are defined by using the top level key "container" to define the :doc:`base-modul`
        configuration.
