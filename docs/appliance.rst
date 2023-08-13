Appliance Configuration
#######################

This module contains documentation for system level configuration applicable for Appliance (VM) based Verify Access
deployments. Container configuration is defined under the ``container`` top level key. At a minimum an administrator
should define the ``isva_base_url``, ``isva_admin_user`` and ``isva_admin_password`` keys (or define the applicable
environment variables).


Example
=======

.. code-block:: yaml

  appliance:
    admin_cfg:
      session_timeout: 720
    activation: #Module activation codes
      webseal: !environment ISVA_BASE_CODE
      access_control: !environment ISVA_AAC_CODE
      federation: !environment ISVA_FED_CODE
    network:
      routes:
      - enabled: True
        comment: "Default route"
        address: "default"
        gateway: "192.168.42.1"
        interface: "1.1"
      interfaces:
      - label: "1.1"
        comment: "Default Interface"
        enabled: True
        ipv4:
          dhcp:
            enabled: False
            allow_management: False
            provides_default_route: False
          addresses:
          - address: "192.168.42.101"
            mask_or_prefix: "24"
            broadcast_address: "192.168.42.255"
            allow_management: True
            enabled: True
          - address: "192.168.42.102"
            mask_or_prefix: "24"
            broadcast_address: "192.168.42.255"
            allow_management: False
            enabled: True
        ipv6:
          dhcp:
            enabled: False
            allowManagement: False
      dns:
        auto: False
        primary_server: "9.9.9.9"


.. _appliance:

Appliance specific configuration
================================
This section covers the configuration options which are only available on appliance or Virtual Machine deployments of 
Verify Access.


.. include:: base.rst



FIPS Compliance
===============
Verify Access can be configured to FIPS compliance when required. FIPS compliance can only be enabled on new (unconfigured) 
appliances and should be enabled before any other configuration options are applied.


.. autoclass::  src.verify_access_autoconf.configure.ISVA_Configurator.FIPS
   :members:


.. _appliance-networking:

Networking
==========
The networking settings can be used to define networking routes, as well as interface address, netmask and gateway 
setting on a Verify Access appliance. Care must be taken when configuring network interfaces to ensure that the 
interface used to configure the appliance is not changed (as this will result in the automation tool failing).

    .. note:: Interfaces can only be updated using the LMI, they cannot be created.


.. autoclass::  src.verify_access_autoconf.appliance.Appliance_Configurator.Networking
   :members:


.. _appliance-date-time:

Date / Time settings
====================
The date and time settings can be adjusted on a Verify Access appliance or synchronized to a external NTP server. Admins 
are also able to set the time zone of the appliance using canonical name.

To set the Date/Time configuration using either a NTP server or manually setting the date via a formatted string. A 
complete list of the available configuration properties can be found `here <https://ibm-security.github.io/pyisva>`_. 
An example configuration is:


.. autoclass::  src.verify_access_autoconf.appliance.Appliance_Configurator.Date_Time
   :members:


.. _cluster-configuration:

Cluster Configuration
=====================
The cluster configuration options can be used to add additional servers to the Verify Access deployment. Currently only
 external databases (HVDB and config) as well as Verify Access HA servers are supported.

This option is typically used in a container deployment to configure the HVDB connection. A complete list of the available 
configuration properties can be found :ref:`here <pyisva:systemsettings#cluster>`. 

    .. note:: PKI required to connect to any servers should be imported in the previous step.


.. autoclass::  src.verify_access_autoconf.appliance.Appliance_Configurator.Cluster_Configuration
   :members:
