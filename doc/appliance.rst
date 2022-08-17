

Example
=======

.. code-block:: yaml
   appliance:
     admin_cfg:
       session_timeout: 720
     date_time:
       enable_ntp: false
       time_zone: "Australia/Brisbane"
     ssl_certificates:
     - name: "lmi_trust_store"
       signer_certificates:
       - "postgres.crt"
       - "ldap.crt"
     - name: "rt_profile_keys"
       signer_certificates:
       - "postgres.crt"
     network:
       routes:
        address: "192.168.0.1"
        mask_or_prefix: 24
        enabled: true
        comment: "Default gateway"
       interfaces:
         label: "1.1"
         name: "1.1"
         comment: "First interface"
         ipv4:
           dhcp:
             enabled: false
           addresses:
           - enabled: true
             allow_management: True
             address: 192.168.10.1
             mask_or_prefix: 24


.. _appliance::


Appliane specific configuration
===============================
This section covers the configuration options which are only available on appliance or Virtual Machine deployments of 
Verify Access.


.. include:: base.rst


.. _appliance-networking::

Networking
^^^^^^^^^^
The networking settings can be used to define networking routes, as well as interface address, netmask and gateway 
setting on a Verify Access appliance. Care must be taken when configuring network interfaces to ensure that the 
interface used to configure the appliance is not changed (as this will result in the automation tool failing).

.. note:: Interfaces can only be updated using the LMI, they cannot be created.

.. code-block:: yaml
   networking:
     routes:
     interfaces:
       label:
       name:
       comment:
       ipv4:
         dhcp:
           enabled: false
         addresses:
         - enabled: true
           allow_management: True
           address: 192.168.0.1
           mask_or_prefix: 24


.. _appliance-date-time

Date / Time settings
^^^^^^^^^^^^^^^^^^^^
The date and time settings can be adjusted on a Verify Access appliance or synchronized to a external NTP server. Admins 
are also able to set the time zone of the appliance using canonical name.

To set the Date/Time configuration using either a NTP server or manually setting the date via a formatted string. A 
complete list of the avaliable configuration properties can be found `here <https://ibm-security.github.io/pyisva>`_. 
An example configuration is:


.. code-block:: yaml
   date_time:
     enable_ntp: true
     ntp_servers:
     - "1.2.3.4"
     - "4.3.2.1"
     time_zone: "Australia/Brisbane"

.. autoclass:: verify-access-configurator.appliance
   :members:
