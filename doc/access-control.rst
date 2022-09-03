
Example
=======


.. _access_control::

Advanced Access Control module configuration
============================
This section covers the Advanced Access Control (AAC) configuration of a Verify Access deployment. This includes 
configuring the runtime authorization server, risk-based access, SCIM, FIDO2 and MMFA.


.. _access_control_template_file::

HTTP Template Files
^^^^^^^^^^^^^^^^^^^
This configuration option can be used to set files or directories containing HTML files which are compatible with the 
AAC and Federation templating engine. The directory structure of any directories to upload should follow the default 
top level directories. If you are defining a direcotyr it should contian a trailing ``/``. An example configuration is:

.. code-block:: yaml
   template_files:
   - aac/template_files/
   - login.html
   - 2fa.html


.. _access_control_mapping_rule::

Mapping Rules
^^^^^^^^^^^^^
This configuration option can be used to upload different types or categories of JavaScript Mapping Rules. These rules 
are typically used to implement custom buisness logic for a particular integration requirement. The types of mapping rules
supported are:
#TODO

.. note:: Some types of mapping rules are defined elsewhere, eg OIDC pre/post token mapping rules must be defined with 
   the OIDC definition they are associated with.

An example configuration is:

.. code-block:: yaml
   mapping_rules:
     - type: SAML2
       files:
       - saml20.js
       - adv_saml20.js
     - type: InfoMap
       files:
        - mapping_rules/basic_user_email_otp.js
        - mapping_rules/basic_user_sms_otp.js
        - mapping_rules/ad_user_mfa.js
     - type: Fido2
       files:
        - mediator.js


.. _access_control_push_notification::

Push notification service
^^^^^^^^^^^^^^^^^^^^^^^^^
This configuration option can be sued to integrate with Apple/Goole mobile push notification service.

#TODO


.. _access_control_server_connections::

Server Connections
^^^^^^^^^^^^^^^^^^
