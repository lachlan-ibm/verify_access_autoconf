Container Configuration
########################

This module contains documentation for system level configuration applicable for Container based Verify Access
deployments. Container configuration is defined under the ``container`` top level key. At a minimum an administrator
should define the ``isva_base_url``, ``isva_admin_user`` and ``isva_admin_password`` keys (or define the applicable
environment variables).


Example
=======


.. code-block:: yaml

   container:
     admin_cfg:
       session_timeout: 720
     account_management:
       users:
       - name: "cfgsvc"
         operation: "update"
         password: !secrets/isva-secrets:cfgsvc-passwd
     management_authorization:
       authorization_enforcement: True
       roles:
       - operation: update
         name: "Configuration Service"
         users:
         - name: "cfgsvc"
           type: "local"
         features:
         - name: "shared_volume"
           access: "w"
     ssl_certificates:
     - name: "lmi_trust_store"
       signer_certificates:
       - "postgres.crt"
       - "ldap.crt"
     - name: "rt_profile_keys"
       signer_certificates:
       - "postgres.crt"
     cluster:
       host: "postgresql"
       port: 5432
       type: "Postgresql"
       user: "postgres"
       password: !secrets/isva-secrets:postgres-passwd
       ssl: True
       db_name: "isva"


.. _container:

Container specific configuration
================================
This section covers the Container specific configuration of Verify Access deployments. Typically this involves setting
an external HVDB connection; and enabling the management authorization feature to permit a service account to publish
configuration snapshots which can be subsequently fetched by other containers in` the deployment.


.. include:: base.rst


.. _managing-container-deployments:

Managing Container Deployments
==============================

Kubernetes / OpenShift
----------------------
If Verify Access is deployed with Kubernetes, then ``kubectl`` cli tool can be used to promote a configuration snapshot. There are
two ways to do this: One, use Kubernetes to restart the deployments; Two, use the automated service from the legacy
"all-in-one" container. It is recommended to use Kubernetes to rollout restarts to deployments where possible.

The ``kubectl rollout restart`` command can be used to restart reverse proxy, runtime and DSC deployments. The configurator
can use deployment names to request a restart of all of the pods associated with a deployment. If this functionality is
used then the user running the Kubernetes commands must have sufficient privilege to restart the containers. An example
of a deployment configuration is::

                                 container:
                                   k8s_deployments:
                                     namespace: "default"
                                     configuration:
                                     - "isamconfig"
                                     webseal:
                                     - "isamwrp_1"
                                     - "isamwrp_2"
                                     runtime:
                                     - "isamruntime"
                                     dsc:
                                     - "isamdsc_1"
                                     - "isamdsc_2"


Docker-Compose
--------------
If Verify Access is deployed with Docker-Compose, then ``docker-compose`` clit tool can be used to manage runtime
containers when a snapshot needs to be promoted. The configurator can use the compose service names to request a restart 
of runtime containers. If this functionality is used then the user running the configurator should have sufficient 
privilege to restart docker containers. 
An example of a compose deployment configuration is::

                                                     container:
                                                       compose_services:
                                                         - "isvawrprp1"
                                                         - "isvaruntime"
                                                       docker_compose_yaml: "iamlab/docker-compose.yaml"


.. _runtime-database-configuration:

Database Configuration
======================
The database configuration for container deployments can be done using the :ref:`cluster-configuration` entry.

.. autoclass:: src.verify_access_autoconf.container.Docker_Configurator.Cluster_Configuration
