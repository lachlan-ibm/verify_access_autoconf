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
The configuration process is broken into six modules. Each module is responsible for configuring a subset of
Verify Access features. The order of configuration is:
 - base
 - appliance (if applicable)
 - container (if applicable)
 - webseal
 - access control
 - federations

Users should take care to ensure the configuration of these separate features are compatible (eg. conflicting ALC's
in a WebSEAL reverse proxy).


.. toctree::
   :maxdepth: 2
   :caption: Contents:
   base
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
