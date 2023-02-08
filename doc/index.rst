.. verify-access-autoconf documentation master file, created by
   sphinx-quickstart on Tue Jul 19 14:23:54 2022.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to verify-access-autoconf documentation!
==================================================
verify-access-configuratior is an automation layer written on top of pyISVA. THis library should be used to apply 
YAML configuration files to a Verify Access deployment.

This library is designed to work with both Appliance and Contaienr based deployments, and is not idempotent.


Installation
------------
You can install ``verify-access-autoconf`` with ``pip``:

.. code-block:: console
    $ pip install verify-access-autoconf

.. _verify_access_autoconf_architecture

Architecture
------------

Users should take care to ensure the configuration of these separate features are compatible (eg. conflicting ALC's
in a WebSEAL reverse proxy).

Example configurations can be found in the ``examples`` directory with additional documentation `here <examples>`.


Modules
_______

The configuration process is broken into six modules. Each module is responsible for configuring a subset of
Verify Access features. The order of configuration is:
 - base
 - appliance (if applicable)
 - container (if applicable)
 - webseal
 - access control
 - federations

YAML configuration keywords
___________________________

Each module expects a YAML object describing the desired configuration state. There are a number of useful features 
which can be used to make configuration files re-usable and version controlled. There are three keywords which 
can be used in configuration files:

 - ``!include``: Used to include a YAML configuration file as the value of the given key. This file can be either an 
                absolute path or relative to the ``ISVA_CONFIG_BASE`` environment variable. eg::

                                                                                                webseal: !include webseal.yaml

 - ``!secret``: Used to set the value of the given key as a value read from the given Kubernetes Secret Namespace/Name,
                eg::

                    admin_password: !secret default/isva-secrets:admin_secret

 - ``!environment``: Used to set the value of the given key as the value read fronm the given environment variable,
                    eg::

                        admin_password: !secret ISVA_ADMIN_SECRET

Environment properties
______________________

In addition to the supplied YAML configuration, some properties can alternatibely be set as environment variables. If
these variables are set, they take priority over values set in configuration files.

- ``ISVA_CONFIG_BASE``: This variable is the root directory of all configuration files for the given Verify Access 
                        Deployment. This can include: YAML configuration files; HTML template pages; JavaScript mapping
                        rules; XML configuration files.
                        If this environment varaiable is not set then the user's ``$HOME`` directory is used.

- ``ISVA_CONFIG_YAML``: This variable defines the YAML configuration file to deploy. This can be either relative
                        to the ``ISVA_CONFIG_BASE`` directory or an absolute file path. If this variable is not defined 
                        then the configuration will look for a file called ``config.yaml`` in the ``ISVA_CONFIG_BASE``
                        directory.

- ``ISVA_MGMT_BASE_URL``: This variable is the URL address that Verify Access Local Management Interface is responding 
                          on. This should contain: the https scheme; the domain or IP address; and a port if not the 
                          standard (443) port. eg: ``https://127.0.0.2:9443``.

- ``ISVA_MGMT_USER``: The user to perform configuration as. This user should have sufficient permissions to configure 
                      all of the features in your YAML configuration file.

- ``ISVA_MGMT_PWD``: The password required to authenticate as the user defined by ``ISVA_MGMT_USER``.

- ``ISVA_MGMT_OLD_PWD``: If a password change is required then this varible defines the password for ``ISVA_MGMT_USER``
                         before the configuration is applied.

- ``ISVA_KUBERNETES_YAML_CONFIG``: This variable defines the Kubernetes cluster configuration file required to run ``kubectl``
                                   commands. This configuration file should have sufficient permission in your cluster 
                                   to restart deployments and pods in the namespace that Verify Access is deployed to.
                                   The file path can either be absolute or relative to the ``ISVA_CONFIG_BASE`` variable.
                                   *note:* This is only applicable for Container deployments using Kubernetes orchestration.

- ``ISVA_DOCKER_COMPOSE_CONFIG``: This varible defines the Docker-Compose deployment configuration file required to run
                                  ``docker-compose`` commands for your Verify Access deployment. This file path can 
                                  either be absolute or relative to the ``ISVA_CONFIG_BASE`` variable.
                                  *note:* This is only applicable for Container deployments using Docker-Compose 
                                          orchestration.

- ``ISVA_CONFIGURATOR_LOG_LEVEL``: This varible set the logging level for the configurator. The default log level is 
                                   ``INFO``.



Detailed information on configuration object strucutre can be found in the submodule documentation

.. toctree::
   :maxdepth: 2
   :caption: Contents:
   appliance
   container
   access-control
   federations
   webseal


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
