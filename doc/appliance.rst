
.. _appliance::

Appliane specific configuration
===============================
This section covers the configuration options which are only available on appliance or Virtual Machine deployments of 
Verify Access.


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

.. code-block:: yaml
   date_time:
     enable_ntp: false
     time_zone: Australia/Brisbane
     ntp_servers:
     - 192.168.0.1


.. autoclass:: verify-access-configurator.appliance
   :members:
