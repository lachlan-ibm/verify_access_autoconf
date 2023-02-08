#!/bin/python
import sys
import os
import logging
import json
import requests
import yaml
import pyisva
import time

from .appliance import Appliance_Configurator as APPLIANCE
from .container import Docker_Configurator as CONTAINER
from .access_control import AAC_Configurator as AAC
from .webseal import WEB_Configurator as WEB
from .federation import FED_Configurator as FED
from .util.data_util import Map, FILE_LOADER
from .util.configure_util import deploy_pending_changes, creds, old_creds, config_base_dir, mgmt_base_url, config_yaml
from .util.constants import API_HEADERS, HEADERS, LOG_LEVEL

logging.basicConfig(stream=sys.stdout, level=os.environ.get(LOG_LEVEL, logging.DEBUG))
_logger = logging.getLogger(__name__)

class ISVA_Configurator(object):
    #Only restart containers if we import PKI or apply a license
    needsRestart = False

    def old_password(self, config_file):
        rsp = requests.get(mgmt_base_url(config_file), auth=old_creds(config_file), headers=HEADERS, verify=False)
        if rsp.status_code == 403:
            return False
        return True


    def lmi_responding(self, config_file):
        url = mgmt_base_url(config_file)
        for _ in range(12):
            try:
                rsp = requests.get(url, verify=False, allow_redirects=False, timeout=6)
                _logger.debug("\trsp.sc={}; rsp.url={}".format(rsp.status_code, rsp.headers.get('Location', 'NULL')))
                if rsp.status_code == 302 and 'Location' in rsp.headers and '/core/login' in rsp.headers['Location']:
                    _logger.info("LMI returning login page")
                    return True
            except:
                pass # Wait and try again
            _logger.debug("\t{} not responding yet".format(url))
            time.sleep(15)
        return False


    '''
    If the ``mgmt_old_pwd`` key is included then the configurator will attempt to update the administrator user's
    password before proceeding configuration. If the password update fails but the administrator is able to successfully
    authenticate (ie. password has already been updated) then configuration will still proceed.

    *note:* These properties are overridded by ``ISVA_MGMT_*`` environment variables

    Example::
              mgmt_user: 'administrator'
              mgmt_pwd: 'S3cr37Pa55w0rd!'
              mgmt_old_pwd: 'administrator'
    '''
    def set_admin_password(self, old, new):
        response = self.factory.get_system_settings().sysaccount.update_admin_password(old_password=old[1], password=new[1])
        if response.success == True:
            _logger.info("Successfullt updated admin password")
        else:
            _logger.error("Failed to update admin password:/n{}".format(response.data))


    '''
    The configurator will always try to accept the Software License Agreement. This does not require any confiuration.
    '''
    def accept_eula(self):
        payload = {"accepted": True}
        rsp = self.factory.get_system_settings().first_steps.set_sla_status()
        if rsp.success == True:
            _logger.info("Accepted SLA")
        else:
            _logger.error("Failed to accept SLA:\n{}".format(rsp.data))


    '''
    The configurator will alway try to complete the Local Management Interface initalization. This does not require
    any configuration.
    '''
    def complete_setup(self):
        if self.factory.get_system_settings().first_steps.get_setup_status().json.get("configured", True) == False:
            rsp = self.factory.get_system_settings().first_steps.set_setup_complete()
            assert rsp.status_code == 200, "Did not complete setup"
            deploy_pending_changes(self.factory, self.config, restartContainers=False)
            _logger.info("Completed setup")


    def _apply_license(self, module, code):
        # Need to activate appliance
        rsp = self.factory.get_system_settings().licensing.activate_module(code)
        if rsp.success == True:
            _logger.info("Successfully applied {} licence".format(module))
            self.needsRestart = True
        else:
            _logger.error("Failed to apply {} license:\n{}".format(module, rsp.data))

    def _activateBaseAppliance(self, config):
        if config.activation is not None and config.activation.webseal is not None:
            _logger.debug("Activating base module")
            self._apply_license("wga", config.activation.webseal)

    def _activateAdvancedAccessControl(self, config):
        if config.activation is not None and config.activation.access_control is not None:
            _logger.debug("Activating access control module")
            self._apply_license("mga", config.activation.access_control)

    def _activateFederation(self, config):
        if config.activation is not None and config.activation.federation is not None:
            _logger.debug("Activating federations module")
            self._apply_license("federation", config.activation.federation)


    '''
    :var: activation:: Dictionary with three keys; one for each optional Verify Access license module which can
                       be activated in a deployment.

                    :var: webseal:: License code for the WebSEAL Reverse Proxy module
                    :var: access_control:: License code for the Advanced Access Control module.
                    :var: federation:: License for the Federations module.

    Example::

              activation:
                base: "example"
                aac: !secret verify-access/isva-secrets:access_control_code
                fed: !environment ISVA_ACCESS_CONTROL_CODE

    '''
    def activate_appliance(self, config):
        system = self.factory.get_system_settings()
        activations = system.licensing.get_activated_modules().json
        _logger.debug("Exisitng activations: {}".format(activations))
        if not any(module.get('id', None) == 'wga' and module.get('enabled', "False") == "True" for module in activations):
            self._activateBaseAppliance(config)
        if not any(module.get('id', None) == 'mga' and module.get('enabled', "False") == "True" for module in activations):
            self._activateAdvancedAccessControl(config)
        if not any(module.get('id', None) == 'federation' and module.get('enabled', "False") == "True" for module in activations):
            self._activateFederation(config)
        if self.needsRestart == True:
            deploy_pending_changes(self.factory, self.config)
            self.needsRestart = False
        _logger.info("appliance activated")


    def _import_signer_certs(self, database, parsed_file):
        ssl = self.factory.get_system_settings().ssl_certificates
        rsp = ssl.import_signer(database, os.path.abspath(parsed_file['path']), label=parsed_file['name'])
        if rsp.success == True:
            _logger.info("Successfully uploaded {} signer certificate to {}".format(
                parsed_file['name'], database))
            self.needsRestart = True
        else:
            _logger.error("Failed to upload {} signer certificate to {} database\n{}".format(
                parsed_file['name'], database, rsp.data))


    def _load_signer_certificates(self, database, server, port, label):
        ssl = self.factory.get_system_settings().ssl_certificates
        rsp = ssl.load_signer(database, server, port, label)
        if rsp.success == True:
            _logger.info("Successfully loaded {} signer certificate to {}".format(
                str(server) + ":" + str(port), database))
            self.needsRestart = True
        else:
            _logger.error("Failed to load {} signer certificate to {}/n{}".format(
                str(server) + ":" + str(port), database, rsp.data))


    def _import_personal_certs(self, database, parsed_file):
        ssl = self.factory.get_system_settings().ssl_certificates
        rsp = ssl.import_personal(database, os.path.abspath(parsed_file['path']))
        if rsp.success == True:
            _logger.info("Successfully uploaded {} personal certificate to {}".format(
                parsed_file['name'], database))
            self.needsRestart = True
        else:
            _logger.error("Failed to upload {} personal certificate to {}/n{}".format(
                parsed_file['name'], database, rsp.data))

    '''
    :var: ssl_certificates:: List of dictionaries which describe the SSL database and the PKI files which should be
                            imported into a particular database.

                            :var: database:: Name of SSL database to configure. If database does not exist it will be
                                             created.
                            :var: personal_certificates:: List of file paths for personal certificates (PKCS#12) to import.
                            :var: signer_certificates:: List of file paths for signer certificates (PEM or DER) to import.

    Example::

              ssl_certificates:
                - database: "lmi_trust_store"
                  personal_certificates:
                    - "ssl/lmi_trust_store/personal"
                  signer_certificates:
                    - "ssl/lmi_trust_store/signer"
                - database: "rt_profile_keys"
                  signer_certificates:
                    - "ssl/rt_profile_keys/signer"


    '''
    def import_ssl_certificates(self, config):
        ssl_config = config.ssl_certificates
        ssl = self.factory.get_system_settings().ssl_certificates
        if ssl_config:
            old_databases = [d['id'] for d in ssl.list_databases().json]
            for database in ssl_config:
                if database.name not in old_databases:
                    rsp = ssl.create_database(database.name, type='kdb')
                    if rsp.success == True:
                        _logger.info("Successfully created {} SSL Ceritificate database".format(
                            database.name))
                    else:
                        _logger.error("Failed to create {} SSL Certificate database".format(
                            database.name))
                        continue
                if database.signer_certificates:
                    for fp in database.signer_certificates:
                        signer_parsed_files = FILE_LOADER.read_files(fp)
                        for parsed_file in signer_parsed_files:
                            self._import_signer_certs(database.name, parsed_file)
                if database.personal_certificates:
                    for fp in database.personal_certificates:
                        personal_parsed_files = FILE_LOADER.read_files(fp)
                        for parsed_file in personal_parsed_files:
                            self._import_personal_certs(database.name, base_dir, parsed_file)
                if database.load_certificates:
                    for item in database.load_certificates:
                        self._load_signer_cert(database.name, item.server, item.port, item.label)
        if self.needsRestart == True:
            deploy_pending_changes(self.factory, self.config)
            self.needsRestart == False


    '''
    :var: admin_cfg:: The complete list of properties that can be set by this key can be found at
                      :ref:`pyisva:systemsettings#administrator-settings`

    Examples::

               admin_cfg:
                 session_timeout: 7200
                 sshd_client_alive: 300
                 console_log_level: "AUDIT"
                 accept_client_certs: true

    '''
    def admin_config(self, config):
        if config.admin_config != None:
            rsp = self.factory.get_system_settings().admin_settings.update(**config.admin_config)
            if rsp.success == True:
                _logger.info("Successfullt set admin config")
            else:
                _logger.error("Failed to set admin config using:\n{}\n{}".format(
                    json.dumps(config.admin_config), rsp.data))


    def _system_users(self, users):
        for user in users:
            rsp = None
            if user.operation == "add":
                rsp = self.factory.get_system_settings().sysaccount.create_user(
                        user=user.name, password=user.password, groups=user.groups)
            elif user.operation == "update":
                if user.password != None:
                    rsp = self.factory.get_system_settings().sysaccount.update_user(
                            user.name, password=user.password)
                    if rsp.success == True:
                        _logger.info("Successfully update passsword for {}".format(user.name))
                    else:
                        _logger.error("Failed to update password for {}:\n{}".format(
                            user.name, rsp.data))
                if user.groups != None:
                    for g in user.groups:
                        rsp = self.factory.get_system_settings().sysaccount.add_user(
                                group=g, user=user.name)
                        if rsp.success == True:
                            _logger.info("Successfully added {} to {} group".format(
                                user.name, g))
                        else:
                            _logger.error("Failed to add {} to {} group:\n{}".format(
                                user.name, g, rsp.data))
            elif user.operation == "delete":
                rsp = self.factory.get_system_settings().sysaccount.delete_user(user.name)
                if rsp.success == True:
                    _logger.info("Successfully removed user {}".format(user.name))
                else:
                    _logger.error("Failed to remove system user {}:\n{}".format(
                        user.name, rsp.data))

    def _system_groups(self, groups):
        for group in config.account_management.groups:
            rsp = None
            if group.operation == "add" or group.operation == "update":
                rsp = self.factory.get_system_settings().sysaccount.create_group(group.id)
            elif group.operation == "delete":
                rsp = self.factory.get_system_settings().sysaccount.delete_group(group.id)
            else:
                _logger.error("oepration {} is not permited for groups".format(group.operation))
                continue
            if rsp.success == True:
                _logger.info("Successfully {} group {}".format(group.operation, group.id))
            else:
                _logger.error("Faield to {} group {}:\n{}\n{}".format(
                    group.operation, group.id, json.dumps(group, indent=4), rsp.data))

            if group.operation == "update":
                for user in group.users:
                    rsp = self.factory.get_system_settings().sysaccount.add_user(user=user, group=group.id)
                    if rsp.success == True:
                        _logger.info("Successfully added {} to group {}".format(user, group.id))
                    else:
                        _logger.error("Faield to add user {} to group {}:\n{}\n{}".format(
                            user, group.id, json.dumps(group, indent=4), rsp.data))


    '''
    :var: account_management:: Dictionary with two keys: one for users to be configured and one for groups to be
                               configured

                            :var: groups:: List of dictionaries. Each dictionary contains a group to be created or updated.
                                          *note*: Groups are created before users; therefore if a user is being created
                                                  and added to a group then

                                        :var: id:: Name of group to create.
                                        :var: users:: List of users to add to group. Users must already exist.

                            :var: users:: List of dictionaries. Each dictionary contains a user to be added, updated or
                                          deleted from the list of Administrator users. Each user must define a name
                                          and operation

                                        :var: name:: Name of the user to create or update.
                                        :var: operation:: "create" || "update" || "delete".
                                        :var: password:: Password to authenticate as user. Required if creating user.
                                        :var: groups:: List of groups to add user to.

    Examples::
            account_management:
              users:
              - name: "cfgsvc"
                operation: "update"
                password: "Passw0rd"
                groups:
                - "aGroup"
                - "anotherGroup"
             groups:
             - name: "adminGroup"
               operation: "update"
               users:
               - "admin"
               - "anotherUser"

    '''
    def account_management(self, config):
        if config.account_management != None:
            if config.account_management.groups != None:
                self._system_groups(config.account_management.groups)
            if config.account_management.users != None:
                self._system_users(config.account_management.users)

    def _add_auth_role(self, role):
        if role.operation == "delete":
            rsp = self.factory.get_system_settings().manangemetauthorization.delete_role(role.name)
            if rsp.success == True:
                _logger.info("Successfully removed {} authorization role".format(role.name))
            else:
                _logger.error("Failed to remove {} authroization role:\n{}".format(
                    role.name, rsp.data))
        elif role.operation in ["add", "update"]:
            configured_roles = self.factory.get_system_settings().managementauthorization.get_roles().json
            exists = False
            for r in configured_roles:
                if r['name'] == role.name:
                    exits = True
                    break
            rsp = None
            if exits == True:
                rsp = self.factory.get_system_settings().managementauthorization.update_role(
                        name=role.name, users=role.users, groups=role.groups, features=role.features)
            else:
                rsp = self.factory.get_system_settings().managementauthorization.create_role(
                        name=role.name, users=role.users, groups=role.groups, features=role.features)
            if rsp.success == True:
                _logger.info("Successfully configured {} authprization role".format(role.name))
            else:
                _logger.error("Failed to configure {} authorization role:\n{}".format(
                    role.name, rsp.data))
        else:
            _logger.error("Unknown operation {} for role configuration:\n{}".format(
                role.operation, json.dumps(role, indent=4)))

    '''
    :var: management_authorization:: Dictionary to enable management authorization as well as define role based access
                                     for users and groups via a list of features.

                                :var: roles:: List of dictionaries. Each dictionary defines a set of features to permit
                                              access (read only / read write ) to as well as a list of users and/or 
                                              groups to add to the role.

                                              :var: operation:: operation to perform on role. "add" || "update" || "delete"
                                              :var: name:: Name of role to modify.
                                              :var: users:: List of users to add to role.

                                                            :var: name:: Name of user
                                                            :var: type:: Type of user. "local" || "remote"

                                              :var: groups:: List of groups

                                                            :var: name::
                                                            :var: type::

                                              :var: features::
                                                            :var: name::
                                                            :var: access::

    Example::
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
    '''
    def management_authorization(self, config):
        if config.management_authorization != None and config.management_authorization.roles != None:
            for role in config.management_authorization.roles:
                self._add_auth_role(role)
            if config.management_authorization.authorization_enforcement:
                rsp = self.factory.get_system_settings().managementauthorization.enable(
                        enforce=config.management_authorization.authorization_enforcement)
                if rsp.success == True:
                    _logger.info("Successfully enabled role based authroization")
                else:
                    _logger.error("Failed to enable role based authorization:\n{}".format(rsp.data))

    def advanced_tuning_parameters(self, config):
        if config.advanced_tuning_parameters != None:
            params = self.factory.get_system-settings().advance_tining.list_params().json
            for atp in config.advanced_tuning_parameters:
                if atp.operation == "delete":
                    uuid = None
                    for p in params:
                        if p['key'] == atp.name:
                            uuid = p['uuid']
                            break
                    rsp = self.factory.get_system_settings().advanced_tuning.delete_parameter(uuid=uuid)
                    if rsp.success == True:
                        _logger.info("Successfully removed {} Advanced Tuning Parameter".format(atp.name))
                    else:
                        _logger.error("Failed to remove {} Advanced tuning paramter:\n{}".format(
                            atp.name, rsp.data))
                elif atp.operation == "update":
                    exits = False
                    for p in params:
                        if p['key'] == atp.name:
                            exists = True
                            break
                    rsp = None
                    if exists == True:
                        rsp = self.factory.get_system_settings().advanced_tuning.update_parameter(
                            key=atp.name, value=atp.value, comment=atp.comment)
                    else:
                        rsp = self.factory.get_system_settings().advanced_tuning.create_parameter(
                            key=atp.name, value=atp.value, comment=atp.comment)
                    if rsp.success == True:
                        _logger.info("Successfully updated {} Advanced Tuning Parameter".format(atp.name))
                    else:
                        _logger.error("Failed to update {} Advanced Tuning Parameter with:\n{}\n{}".format(
                            atp.name, json.dupms(atp, indent=4), rsp.data))
                elif atp.operation == "add":
                    rsp = self.factory.get_system_settings().advanced_tuning.create_parameter(
                        key=atp.name, value=atp.value, comment=atp.comment)
                    if rsp.success == True:
                        _logger.info("Successfully add {} Advanced Tuning Parameter".format(atp.name))
                    else:
                        _logger.error("Failed to add {} Advanced Tuning Parameter with:\n{}\n{}".format(
                            atp.name, json.dupms(atp, indent=4), rsp.data))
                else:
                    _logger.error("Unknown operation {} for Advanced Tuning Parameter:\n{}".format(
                        atp.operation, json.dumps(atp, indent=4)))


    def apply_snapshot(self, config):
        if config != None and config.snapshot != None:
            snapshotConfig = config.snapshot
            rsp = self.factory.get_system_settings().snapshot.upload(snapshotConfig.snapshot)
            if rsp.success == True:
                _logger.info("Successfully applied snapsnot [{}]".format(snapshotConfig.snapshot))
                deploy_pending_changes(self.factory, self.config)
            else:
                _logger.error("Failed to apply snapshot [{}]\n{}".foramt(snapshotConfig.snapshot),
                        rsp.content)


    def configure_base(self, appliance, container):
        base_config = None
        model = None
        if self.config.appliance is not None:
            base_config = self.config.applianc
            model = appliance
        elif self.config.container is not None:
            base_config = self.config.container
            model = container
        else:
            _logger.error("Deployment model cannot be found in config.yaml, skipping")
            return
        self.apply_snapshot(base_config)
        self.admin_config(base_config)
        self.import_ssl_certificates(base_config)
        self.account_management(base_config)
        self.management_authorization(base_config)
        self.advanced_tuning_parameters(base_config)
        model.configure()

        self.activate_appliance(base_config)


    def get_modules(self):
        appliance = APPLIANCE(self.config, self.factory)
        container = CONTAINER(self.config, self.factory)
        web = WEB(self.config, self.factory)
        aac = AAC(self.config, self.factory)
        fed = FED(self.config, self.factory)
        return appliance, container, web, aac, fed


    def configure(self, config_file=None):
        _logger.info("Reading configuration file")
        self.config = config_yaml(config_file)
        _logger.info("Testing LMI connectivity")
        if self.lmi_responding(self.config) == False:
            _logger.error("Unable to contact LMI, exiting")
            sys.exit(1)
        _logger.info("LMI responding, begin configuration")
        if self.old_password(self.config):
            self.factory = pyisva.Factory(mgmt_base_url(self.config), *old_creds(self.config))
            self.accept_eula()
            self.complete_setup()
            self.set_admin_password(old_creds(self.config), creds(self.config))
            self.factory = pyisva.Factory(mgmt_base_url(self.config), *creds(self.config))
        else:
            self.factory = pyisva.Factory(mgmt_base_url(self.config), *creds(self.config))
            self.accept_eula()
            self.complete_setup()
        appliance, container, web, aac, fed = self.get_modules()
        self.configure_base(appliance, container)
        web.configure()
        aac.configure()
        fed.configure()

if __name__ == "__main__":
    from isva_configurator import configurator
    configurator.configure()
