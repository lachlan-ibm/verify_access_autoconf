#!/bin/python
"""
@copyright: IBM
"""
import sys
import os
import logging
import json
import requests
import yaml
import pyisva
import time
import typing

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


    class Admin_Password(typing.TypedDict):
        '''
        Example:: 

            mgmt_user: 'administrator'
            mgmt_pwd: 'S3cr37Pa55w0rd!'
            mgmt_old_pwd: 'administrator'

        *note:* These properties are overridden by ``ISVA_MGMT_*`` environment variables

        '''

        mgmt_user: str
        'Administrator user to run configuration as.'

        mgmt_pwd: str
        'Secret to authenticate as the Administrator user.'

        mgmt_old_pwd: str
        'Password to update for the Administrator user.'

    def set_admin_password(self, old, new):

        response = self.factory.get_system_settings().sysaccount.update_admin_password(old_password=old[1], password=new[1])
        if response.success == True:
            _logger.info("Successfully updated admin password")
        else:
            _logger.error("Failed to update admin password:/n{}".format(response.data))


    def accept_eula(self):
        payload = {"accepted": True}
        rsp = self.factory.get_system_settings().first_steps.set_sla_status()
        if rsp.success == True:
            _logger.info("Accepted SLA")
        else:
            _logger.error("Failed to accept SLA:\n{}".format(rsp.data))


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
            _logger.info("Successfully applied {} license".format(module))
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



    class Module_Activations(typing.TypedDict):
        '''
        Example::

                  activation:
                    webseal: "example"
                    access_control: !secret verify-access/isva-secrets:access_control_code
                    federation: !environment ISVA_ACCESS_CONTROL_CODE

        '''

        webseal: typing.Optional[str]
        'License code for the WebSEAL Reverse Proxy module.'

        access_control: typing.Optional[str]
        'License code for the Advanced Access Control module.'

        federation: typing.Optional[str]
        'License for the Federations module.'

    def activate_appliance(self, config):
        system = self.factory.get_system_settings()
        activations = system.licensing.get_activated_modules().json
        _logger.debug("Existing activations: {}".format(activations))
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

    class SSL_Certificates(typing.TypedDict):
        '''
        Example::

                  ssl_certificates:
                  - database: "lmi_trust_store"
                    personal_certificates:
                    - path: "ssl/lmi_trust_store/personal"
                      secret: "S3cr37"
                    signer_certificates:
                    - "ssl/lmi_trust_store/signer"
                  - database: "rt_profile_keys"
                    signer_certificates:
                    - "ssl/rt_profile_keys/signer"

        '''

        database: str
        'Name of SSL database to configure. If database does not exist it will be created.'

        signer_certificates: typing.Optional[typing.List[str]]
        'List of file paths for signer certificates (PEM or DER) to import.'


        class Personal_Certificate(typing.TypedDict):
            path: str
            'Path to file to import as a personal certificate'

            secret: typing.Optional[str]
            'Optional secret to decrypt personal certificate'

        personal_certificates: typing.Optional[typing.List[Personal_Certificate]]
        'List of file paths for personal certificates (PKCS#12) to import.'

    def import_ssl_certificates(self, config):
        ssl_config = config.ssl_certificates
        ssl = self.factory.get_system_settings().ssl_certificates
        if ssl_config:
            old_databases = [d['id'] for d in ssl.list_databases().json]
            for database in ssl_config:
                if database.name not in old_databases:
                    rsp = ssl.create_database(database.name, type='kdb')
                    if rsp.success == True:
                        _logger.info("Successfully created {} SSL Certificate database".format(
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


    class Admin_Config(typing.TypedDict):
        '''
        Examples::

                   admin_cfg:
                     session_timeout: 7200
                     sshd_client_alive: 300
                     console_log_level: "AUDIT"
                     accept_client_certs: true

        The complete list of properties that can be set by this key can be found at :ref:`pyisva:systemsettings#administrator-settings`
        '''

        session_timeout: typing.Optional[int]
        sshd_client_alive: typing.Optional[int]
        enabled_tls: typing.Optional[typing.List[str]]
        console_log_level: typing.Optional[str]
        accept_client_certs: typing.Optional[bool]
        log_max_files: typing.Optional[int]
        log_max_size: typing.Optional[int]
        http_proxy: typing.Optional[str]
        https_proxy: typing.Optional[str]

    def admin_config(self, config):
        if config.admin_config != None:
            rsp = self.factory.get_system_settings().admin_settings.update(**config.admin_config)
            if rsp.success == True:
                _logger.info("Successfully set admin config")
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
                        _logger.info("Successfully update password for {}".format(user.name))
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
                _logger.error("Operation {} is not permitted for groups".format(group.operation))
                continue
            if rsp.success == True:
                _logger.info("Successfully {} group {}".format(group.operation, group.id))
            else:
                _logger.error("Failed to {} group {}:\n{}\n{}".format(
                    group.operation, group.id, json.dumps(group, indent=4), rsp.data))

            if group.operation == "update":
                for user in group.users:
                    rsp = self.factory.get_system_settings().sysaccount.add_user(user=user, group=group.id)
                    if rsp.success == True:
                        _logger.info("Successfully added {} to group {}".format(user, group.id))
                    else:
                        _logger.error("Failed to add user {} to group {}:\n{}\n{}".format(
                            user, group.id, json.dumps(group, indent=4), rsp.data))


    class Account_Management(typing.TypedDict):
        '''
        Example::

                account_management:
                  users:
                  - name: !secret default/isva-secrets:cfgsvc_user
                    operation: "update"
                    password: !secret default/isva-secrets:cfgsvc_secret
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
        class Management_User(typing.TypedDict):
            operation: str
            'Operation to perform with user. "add" | "update" | delete".'

            name: str
            'Name of the user to create, remove or update.'

            password: typing.Optional[str]
            'Password to authenticate as user. Required if creating user.'

            groups: typing.Optional[typing.List[str]]
            'Optional list of groups to add user to.'


        class Management_Group(typing.TypedDict):
            '''
            *note*: Groups are created before users; therefore if a user is being created and added to a group then
                    this should be done in the user configuration entry.
            '''
            operation: str
            'Operation to perform with group. "add" | "update" | delete".'

            id: str
            'Name of group to create.'

            users: typing.Optional[typing.List[str]]
            'Optional list of users to add to group.'

        users: typing.Optional[typing.List[Management_User]]
        'Optional list of management users to configure'

        groups: typing.Optional[typing.List[Management_Group]]
        'Optional list of management groups to configure.'

    def account_management(self, config):
        if config.account_management != None:
            if config.account_management.groups != None:
                self._system_groups(config.account_management.groups)
            if config.account_management.users != None:
                self._system_users(config.account_management.users)

    def _add_auth_role(self, role):
        if role.operation == "delete":
            rsp = self.factory.get_system_settings().mgmt_authorization.delete_role(role.name)
            if rsp.success == True:
                _logger.info("Successfully removed {} authorization role".format(role.name))
            else:
                _logger.error("Failed to remove {} authorization role:\n{}".format(
                    role.name, rsp.data))
        elif role.operation in ["add", "update"]:
            configured_roles = self.factory.get_system_settings().mgmt_authorization.get_roles().json
            exists = False
            for r in configured_roles:
                if r['name'] == role.name:
                    exits = True
                    break
            rsp = None
            if exits == True:
                rsp = self.factory.get_system_settings().mgmt_authorization.update_role(
                        name=role.name, users=role.users, groups=role.groups, features=role.features)
            else:
                rsp = self.factory.get_system_settings().mgmt_authorization.create_role(
                        name=role.name, users=role.users, groups=role.groups, features=role.features)
            if rsp.success == True:
                _logger.info("Successfully configured {} authorization role".format(role.name))
            else:
                _logger.error("Failed to configure {} authorization role:\n{}".format(
                    role.name, rsp.data))
        else:
            _logger.error("Unknown operation {} for role configuration:\n{}".format(
                role.operation, json.dumps(role, indent=4)))


    class Management_Authorization(typing.TypedDict):
        '''
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

        class Role(typing.TypedDict):
            class User(typing.TypedDict):
                name: str
                'Name of user'
                type: str
                'Type of user. "local" | "remote".'

            class Group(typing.TypedDict):
                name: str
                'name of group.'
                type: str
                'Type of group. "local" | "remote".'

            class Feature(typing.TypedDict):
                name: str
                'Name of feature.'
                access: str
                'Access to grant to feature. "r" | "w".'

            operation: str
            'Operation to perform on authorization role. "add" | "remove" | "update".'
            name: str
            'Name of role.'
            users: typing.Optional[typing.List[User]]
            'Optional list of users to add to role.'
            groups: typing.Optional[typing.List[Group]]
            'Optional list of groups to add to role.'
            features: typing.List[Feature]
            'List of features to authorize users / groups for.'

        authorization_enforcement: bool
        'Enable role based authorization for this deployment.'

        roles: typing.Optional[typing.List[Role]]
        'Optional list of roles to modify for role based authorization.'

    def management_authorization(self, config):
        if config.management_authorization != None and config.management_authorization.roles != None:
            for role in config.management_authorization.roles:
                self._add_auth_role(role)
            if config.management_authorization.authorization_enforcement:
                rsp = self.factory.get_system_settings().mgmt_authorization.enable(
                        enforce=config.management_authorization.authorization_enforcement)
                if rsp.success == True:
                    _logger.info("Successfully enabled role based authorization")
                else:
                    _logger.error("Failed to enable role based authorization:\n{}".format(rsp.data))


    class Advanced_Tuning_Parameter:
        '''
        Example::

                  advanced_tuning_parameters:
                  - name: "wga.rte.embedded.ldap.ssl.port"
                    value: 636
                  - name: "password.policy"
                    value: "minlen=8 dcredit=1 ucredit=1 lcredit=1"
                    description: "Enforced PAM password quality for management accounts."

        '''
        name: str
        'Name of the Advanced Tuning Parameter.'
        value: str
        'Value of the Advanced Tuning Parameter.'
        description: typing.Optional[str]
        'optional description of the Advanced Tuning Parameter.'

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
                        _logger.error("Failed to remove {} Advanced Tuning Parameter:\n{}".format(
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
                            atp.name, json.dumps(atp, indent=4), rsp.data))
                elif atp.operation == "add":
                    rsp = self.factory.get_system_settings().advanced_tuning.create_parameter(
                        key=atp.name, value=atp.value, comment=atp.comment)
                    if rsp.success == True:
                        _logger.info("Successfully add {} Advanced Tuning Parameter".format(atp.name))
                    else:
                        _logger.error("Failed to add {} Advanced Tuning Parameter with:\n{}\n{}".format(
                            atp.name, json.dumps(atp, indent=4), rsp.data))
                else:
                    _logger.error("Unknown operation {} for Advanced Tuning Parameter:\n{}".format(
                        atp.operation, json.dumps(atp, indent=4)))


    class Snapshot(typing.TypedDict):
        '''
        Example::

                snapshot: "snapshot/isva-2023-02-08.snapshot"

        '''
        snapshot: str
        'Path to signed snapshot archive file.'

    def apply_snapshot(self, config):
        if config != None and config.snapshot != None:
            snapshotConfig = config.snapshot
            rsp = self.factory.get_system_settings().snapshot.upload(snapshotConfig.snapshot)
            if rsp.success == True:
                _logger.info("Successfully applied snapshot [{}]".format(snapshotConfig.snapshot))
                deploy_pending_changes(self.factory, self.config)
            else:
                _logger.error("Failed to apply snapshot [{}]\n{}".format(snapshotConfig.snapshot),
                        rsp.data)


    class Extensions(typing.TypedDict):
        '''
        Example::

                extensions:
                - extension: "Instana/instana.ext"
                  third_party_packages:
                  - "Instana/agent.rpm"
                  properties:
                    extId: "instanaAgent"
                    instanaAgentKey: !environment INSTANA_AGENT_KEY
                    instanaHost: !environment INSTANA_HOST
                    instanaPort: 443
                    mvnRepositoryUrl: "https://artifact-public.instana.io"
                    mvnRepositoryFeaturesPath: "artifactory/features-public@id=features@snapshots@snapshotsUpdate=never"
                    mvnRepositorySharedPath: "artifactory/shared@id=shared@snapshots@snapshotsUpdate=never"
        '''

        extension: str
        'The signed extension file to be installed on Verify Access.'
        third_party_packages: typing.Optional[str]
        'An optional list of third party packages to be uploaded to Verify Access as part of the installation process.'
        properties: typing.Optional[dict]
        'Key-Value properties to give the extension during the installation process. This list of properties will vary with the type of extension being installed.'

    def install_extensions(self, config):
        if config != None and config.extensions != None:
            for extension in config.extensions:
                third_party_files = []
                if extension.third_party_packages != None:
                    for tpp in extension.third_party_packages:
                        third_party_files += FILE_LOADER.read_file(tpp)
                third_party_files = [e.get("path", "INVALID") for e in third_party_files]
                ext_file = optional_list(FILE_LOADER.read_file(extension.extension))[0].get('path', "INVALID")
                rsp = self.factory.get_system_settings().extensions.create_extension(
                                        ext_file=ext_file, properties=properties, third_party_packages=third_party_files)
                if rsp.success == True:
                    _logger.info("Successfully installed {} extension".format(extension.extension))
                else:
                    _logger.error("Failed to install extension:\n{}\n{}".format(
                                            json.dumps(extension, ident=4), rsp.data))


    def configure_base(self, appliance, container):
        base_config = None
        model = None
        if self.config.appliance is not None:
            base_config = self.config.appliance
            model = appliance
        elif self.config.container is not None:
            base_config = self.config.container
            model = container
        else:
            _logger.error("Deployment model cannot be found in config.yaml, skipping container/appliance configuration.")
            return
        self.apply_snapshot(base_config)
        self.admin_config(base_config)
        self.import_ssl_certificates(base_config)
        self.account_management(base_config)
        self.management_authorization(base_config)
        self.advanced_tuning_parameters(base_config)
        model.configure()

        self.activate_appliance(base_config)
        self.install_extensions(base_config)


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
