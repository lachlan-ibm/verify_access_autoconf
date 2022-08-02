
.. _container::

Container specific configuration
================================
This section covers the Container specific configuration of Verify Access deployments. Typically this involves setting 
an external HVDB connection; and enabling the management authorization feature to permit a service account to publish 
configuration snapshots which can be subsequently fetched by other containers in` the deployment.


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
If Verify Access is deployed to Kubernetes, then ``kube`` api can be used to promote a configuration snapshot. The 
``kubectl rollout restart`` command can be used to restart rever proxy, runtime and DSC deployments.

.. code-block:: yaml
   deployments:
    namespace: "default"
    configuration: "isamconfig"
    webseal: "isamwebseal"
    runtime: "isamruntime"
    dsc: "isamdsc"


.. _management-authorization::

Management Authorization
^^^^^^^^^^^^^^^^^^^^^^^^


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
