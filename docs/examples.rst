Example Verify Access Configurations (Getting Started)
######################################################

First Steps
===========

The first steps configuration file defines some initial configuration that is required for all Verify Access deployments.
These steps include:

- Accepting the software license agreement and initial management configuration.
- Configuring service accounts for publishing snapshots to Runtime Containers.
- Importing PKI for the LDAP Runtime Server and High-Volume Runtime Database.
- Applying module licenses for the WebSEAL, Advanced Access Control and Federation modules.
- Configuring the WebSEAL Runtime Policy Server / User Registry.

To run this configuration you should define the following properties, where the "current directory" contains the PKI for the LDAP and HVDB services:

.. code-block:: bash

   export ISVA_CONFIG_BASE="current directory"
   export ISVA_CONFIG_YAML=first_steps.yaml
   export ISVA_MGMT_BASE_URL="https://192.168.42.101"
   export ISVA_MGMT_USER=admin
   export ISVA_MGMT_PWD=betterThanPassw0rd
   export ISVA_MGMT_OLD_PWD=admin
   export ISVA_BASE_CODE="webseal activation code"
   export ISVA_AAC_CODE="access control activation code"
   export ISVA_FED_CODE="federations activation code"
   export LDAP_BIND_PASSWORD=betterThanPassw0rd
   export LDAP_SEC_PASSWORD=betterThanPassw0rd


.. include:: ../examples/first_steps.yaml
   :literal:


First Steps (appliance deployment)
==================================

The first steps configuration file defines some initial configuration that is required for all Verify Access deployments.
These steps include:

- Accepting the software license agreement and initial management configuration.
- Setting network configuration (routes, ip addresses, dns).
- Applying module licenses for the WebSEAL, Advanced Access Control and Federation modules.
- Configuring the WebSEAL Runtime Policy Server / User Registry.

To run this configuration you should define the following properties:

.. code-block:: bash

   export ISVA_CONFIG_YAML=appliance_first_steps.yaml
   export ISVA_MGMT_BASE_URL="https://192.168.42.101"
   export ISVA_MGMT_USER=admin
   export ISVA_MGMT_PWD=betterThanPassw0rd
   export ISVA_MGMT_OLD_PWD=admin
   export ISVA_BASE_CODE="webseal activation code"
   export ISVA_AAC_CODE="access control activation code"
   export ISVA_FED_CODE="federations activation code"
   export LDAP_BIND_PASSWORD=betterThanPassw0rd
   export LDAP_SEC_PASSWORD=betterThanPassw0rd


.. include:: ../examples/appliance_first_steps.yaml
   :literal:


WebSEAL Reverse Proxy using Advanced Access Control authentication
==================================================================

The WebSEAL / AAC deployment defines a Verify Access deployment with a single WebSEAL reverse proxy. This proxy is
configured to perform authentication using the AAC authentication capabilities. The configuration steps performed
include:

- Creating a WebSEAL Reverse Proxy instance
- Integrating the AAC/Federation runtime to provide authentication to WebSEAL
- Enable the Username/Password authentication mechanism
- Create a demo user in the WebSEAL User Registry
- Update the default WebSEAL login page to use AAC


.. include:: ../examples/webseal_authsvc_login.yaml
   :literal:


Installation of the Instana monitoring Agent
============================================

The Instana monitoring example defines a Verify Access deployment where a third party infrastructure monitoring tool (Instana)
is installed onto a Verify Access appliance using a `Verify Access Extension <https://exchange.xforce.ibmcloud.com/hub>`_. This 
extension allows administrators to collect detailed system information (CPU, RAM, Disk, Networking) during runtime. This example 
assumes that you have a valid Instana tenant and have downloaded the latest `Agent RPM <https://packages.instana.io/agent/download>`_ 
for JDK 11. The configuration steps performed include:

- Applying the module licenses
- Set static networking properties
  - Static IPv4 addresses
  - Gateway (default route) settings
  - Set DNS properties
- Install the Instana extension
- Configure the WebSEAL RTE (Policy Server/User Registry)


.. include:: ../examples/instana_monitor.yaml
   :literal:


Mobile Multi-Factor Authentication
==================================

The MMFA example follows the legacy cookbook deployment guide.

*TODO*


Federation
==========

The Federation example follows the legacy cookbook deployment guide

There are a few steps which are required for running this configuration. You must:
- Create PKI for IDP and SP deployments [self-signed demonstration provide]
- Deploy the IdP and SP container deployments from the :ref:`IAMExploring<https://www.github.com/iamexploring/container-deployment>` 
- Obtain an version appropriate copy of the required JavaScript mapping rules
- Run the :ref:`IdP<example_idp_yaml>` and :ref:`SP<example_sp_yaml>` configurations to create the Federations
- Run the :ref:`IdP partner<example_idp_partner_yaml>` and :ref:`SP partner<example_sp_partner_yaml>` configurations to create the Federation Partners
- Create a test user using the demo User Self Care enrollment policy on the IdP deployment
- Test the Federated authentication:
    - IdP initiated SSO
    - SP initiated SSO


.. _example_idp_yaml:

IdP Configuration:
__________________

.. include:: ../examples/federation_idp.yaml
   :literal:

.. _example_sp_yaml:

SP Configuration:
_________________

.. include:: ../examples/federation_sp.yaml
   :literal:

.. _example_idp_partner_yaml:

IdP Partner Configuration:
__________________________

.. include:: ../examples/federation_idp_partner.yaml
   :literal:

.. _example_sp_partner_yaml:

SP Partner Configuration:
_________________________

.. include:: ../examples/federation_sp_partner.yaml
   :literal: