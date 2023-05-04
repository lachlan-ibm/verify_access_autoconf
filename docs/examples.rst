Example Verify Access Configurations (Getting Started)
######################################################

First Steps
===========

The first steps configuration file defines some initial configuration that is required for all Verify Access deployments.
These steps include:

- Accepting the software licence aggreement and initial management configuration.
- Configuring service accounts for publishing snapshots to Runtime Containers.
- Importing PKI for the LDAP Runtime Server and High-Volume Runtime Database.
- Applying module licences for the WebSEAL, Advanced Access Control and Federation modules.
- Configuring the WebSEAL Runtime Policy Server / User Registry.


.. include:: ../examples/first_steps.yaml
   :literal:


WebSEAL Reverse Proxy using Advanced Access Control authentication
==================================================================

The WebSEAL / AAC deployment defines a Verify Access deployment with a single WebSEAL reverse proxy. This proxy is
configured to perform authentication using the AAC authetnication capabilities.


.. include:: ../examples/webseal_authsvc_login.yaml
   :literal:


Mobile Multi-Factor Authentication
==================================

The MMFA example follows the legacy cookbook deployment guide.

*TODO*


Federation
----------

The Federation example follows the legacy cookbook deployment guide

*TODO*
