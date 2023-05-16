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


.. include:: ../examples/first_steps.yaml
   :literal:


WebSEAL Reverse Proxy using Advanced Access Control authentication
==================================================================

The WebSEAL / AAC deployment defines a Verify Access deployment with a single WebSEAL reverse proxy. This proxy is
configured to perform authentication using the AAC authentication capabilities. The configuration steps performed
include:

- Creating a WebSEl Reverse Proxy instance
- Integrating the AAC/Federation runtime to provide authentication to WebSEAL
- Enable the Username/Password authentication mechanism
- Create a demo user in the WebSEAL User Registry
- Update the default WebSEAL login page to use AAC


.. include:: ../examples/webseal_authsvc_login.yaml
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
- Obtain an version appropriate copy of the required JavaScript mapping rules

*TODO*
