

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
         password: @secrets/isva-secrets:cfgsvc-passwd
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
       password: @secrets/isva-secrets:postgres-passwd
       ssl: True
       db_name: "isva"


.. _container::

Container specific configuration
================================
This section covers the Container specific configuration of Verify Access deployments. Typically this involves setting 
an external HVDB connection; and enabling the management authorization feature to permit a service account to publish 
configuration snapshots which can be subsequently fetched by other containers in` the deployment.


.. include:: base.rst


.. _update-container-names

Update container names
^^^^^^^^^^^^^^^^^^^^^^
In kubernetes deployments admins have the option of rolling out changes to runtime/webeal/dsc pods using the pod restart
command. However this poses a problem for version controlled configuration files, as the name of a pod is randomly set 
by Kubernetes, which uses the deployment/image name as a prefix then appends random characters.

To allow admins to accommodate for this, the automation tool has the capability to "learn" what the container names are 
by looking for pods attached to the deployment object. Any pods which are found are added to the configuration YAML, 
where they can be used in subsequent steps to promote a new configuration snapshot using the ``isva_cli`` tool.

.. note:: The promotion of configuration snapshots using the ``isva_cli`` tool is depreciated in the lightweight Verify 
   Access containers. Administrators should migrate to a strategy of using kubernetes to rollout restarts to deployments,
   eg. ``kubectl rollout restart deployment/verify-access-wrp``.

.. code-block:: yaml
  containers:
    namespace: "default"
    configuration: "isamconfig"
    webseal: "isamwebseal"
    runtime: "isamruntime"
    dsc: "isamdsc"


.. _managing-kubernetes-deployments::

Managing Kubernetes Deployments
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
If Verify Access is deployed to Kubernetes, then ``kube`` api can be used to promote a configuration snapshot. There are 
two waysa to do this: One, use Kubernetes to restart the deployments; Two, use the autmoated service from the legacy 
"all-in-one" container. It is recommended to use Kubernetes to rollot restarts to deployments where possible.

The ``kubectl rollout restart`` command can be used to restart rever proxy, runtime and DSC deployments. The configurator 
can use deployment names to request a restgart of all of the pods associated with a deployment. If this functionality is 
used then the user running the Kubernetes commands must have sufficient priveledge to restart the containers. An example 
of a deployment configuration is:

.. code-block:: yaml
   deployments:
    namespace: "default"
    configuration: "isamconfig"
    webseal: "isamwebseal"
    runtime: "isamruntime"
    dsc: "isamdsc"


.. _runtime-database-configuration

Database Configuration
^^^^^^^^^^^^^^^^^^^^^^
The database configuration for container deployments can be done using the :ref:`cluster-configuration` entry.

.. code-block:: yaml
  cluster:
    runtime_database:
      type: "postgresql"
      host: "postgresql"
      port: 5432
      ssl: True
      username: "postgres"
      password: "Passw0rd"
