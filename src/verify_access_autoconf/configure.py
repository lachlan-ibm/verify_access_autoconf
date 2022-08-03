#!/bin/python
import sys
import os
import logging
import json
import requests
import yaml
import pyisva
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

from .appliance import Appliance_Configurator as APPLIANCE
from .container import Docker_Configurator as CONTAINER
from .access_control import AAC_Configurator as AAC
from .webseal import WEAB_Configurator as WEB
from .federation import FED_Configurator as FED
from .util.data_util import Map
from .util.configure_util import deploy_pending_changes, creds, old_creds, config_base_dir, mgmt_base_url
from .util.constants import API_HEADERS, HEADERS

_logger = logging.getLogger(__name__)

class ISVA_Configurator(object):

    def old_password(self):
        rsp = requests.get(MGMT_BASE_URL, auth=OLD_CREDS, headers=HEADERS, verify=False)
        if rsp.status_code == 403:
            return False
        return True


    def set_admin_password(self, old, new):
        response = self.factory.get_system_setting().sysaccount.update_admin_password(old_password=old(1), password=new(1)) 
        if response.success == True:
            _logger.info("Successfullt updated admin password")
        else:
            _logger.error("Failed to update admin password:/n{}".format(response.data))


    def accept_eula(self, creds):
        payload = {"accepted": True}
        rsp = self.factory.get_system_setting().first_steps.set_sla_status()
        if rspsuccess == True:
            _logger.info("Accepted SLA")
        else:
            _logger.error("Failed to accept SLA:\n{}".format(rsp.data))


    def complete_setup(self, creds):
        rsp = self.factory.get_system_setting().first_steps.set_setup_complete()
        assert rsp.status_code == 200, "Did not complete setup"
        deploy_pending_changes()
        _logger.info("Completed setup")


    def _apply_license(self, module, code):
        # Need to activate appliance
        rsp = self.factory.get_system_settings().licensing.activate_module(code)
        if rsp.success == True:
            _logger.info("Successfully applied {} licence".format(module))
        else:
            _logger.error("Failed to apply {} license:\n{}".format(module, rsp.data))

    def _activateBaseAppliance(self):
        code = None
        if self.config.appliance and self.config.appliance.activation:
            code = self.config.appliance.activation.wga
        if not code and self.config.docker and self.config.docker.activation:
            code = self.config.docker.activation.wga
        self._apply_license("wga", code)

    def _activateAdvancedAccessControl(self):
        code = None
        if self.config.appliance and self.config.appliance.activation:
            code = self.config.appliance.activation.mga
        if not code and self.config.docker and self.config.docker.activation:
            code = self.config.docker.activation.mga
        self._apply_license("mga", code)

    def _activateFederation(self):
        code = None
        if self.config.appliance and self.config.appliance.activation:
            code = self.config.appliance.activation.federation
        if not code and self.config.docker and self.config.docker.activation:
            code = self.config.docker.activation.federation
        self._apply_license("federation", code)

    def activate_appliance(self):
        system = self.factory.get_system_settings()
        activations = system.licensing.get_activated_modules().json
        if not any(module.get('id', None) == 'wga' and module.get('enabled', "False") == "True" for module in activations):
            _activateBaseAppliance()
        if not any(module.get('id', None) == 'mga' and module.get('enabled', "False") == "True" for module in activations):
            _activateAdvancedAccessControl()
        if not any(module.get('id', None) == 'federation' and module.get('enabled', "False") == "True" for module in activations):
            _activateFederation()
        deploy_pending_changes()
        _logger.info("appliance activated")


    def _import_signer_certs(self, database, parsed_file):
        ssl = self.factory.get_system_settings().ssl_certificates
        rsp = ssl.import_signer(database, os.path.abspath(base + filePointer), label=filePointer)
        if rsp.success == True:
            _logger.info("Successfully uploaded {} signer certificate to {}".format(
                filePointer, database))
        else:
            _logger.error("Failed to upload {} signer certificate to {} database\n{}".format(
                filePointer, database, rsp.data))


    def _load_signer_certificates(self, database, server, port, label):
        ssl = self.factory.get_system_settings().ssl_certificates
        rsp = ssl.load_signer(database, server, port, label)
        if rsp.success == True:
            _logger.info("Successfully loaded {} signer certificate to {}".format(
                str(server) + ":" + str(port), database))
        else:
            _logger.error("Failed to load {} signer certificate to {}/n{}".format(
                str(server) + ":" + str(port), database, rsp.data))


    def _import_personal_certs(self, database, parsed_file):
        ssl = self.factory.get_system_settings().ssl_certificates
        rsp = ssl.import_personal(database, os.path.abspath(parsed_file['path']))
        if rsp.success == True:
            _logger.info("Successfully uploaded {} personal certificate to {}".format(
                parsed_file['name'], database))
        else:
            _logger.error("Failed to upload {} personal certificate to {}/n{}".format(
                parsed_file['name'], database, rsp.data))

    def import_ssl_certificates(self):
        ssl_config = None
        if self.config.appliance:
            ssl_config = self.config.appliance.ssl_certificates
        elif self.config.docker:
            ssl_config = self.config.docker.ssl_certificates
        ssl = self.factory.get_system_settings().ssl_certificates
        if ssl_config:
            old_databases = [d['id'] for d in ssl.list_databases().json]
            print(old_databases)
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
                            _import_signer_certs(database.name, parsed_file)
                if database.personal_certificates:
                    for fp in database.personal_certificates:
                        personal_parsed_files = FILE_LOADER.read_files(fp)
                        for parsed_file in personal_parsed_files:
                            _import_personal_certs(database.name, base_dir, parsed_file)
                if database.load_certificates:
                    for item in database.load_certificates:
                        _load_signer_cert(database.name, item.server, item.port, item.label)
        deploy_pending_changes()


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
            elif opration == "update":
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
            elif operation == "delete":
                rsp = self.factory.get_system_settings().sysaccount.delete_user(user.name)
                if rsp.success == True:
                    _logger.info("Successfully removed user {}".format(user.name))
                else:
                    _logger.error("Failed to remove system user {}:\n{}".format(
                        user.name, rsp.data))

    def _system_groups(self, groups):
        for group in config.account_management.groups:
            rsp = None
            if group.operation == "add":
                rsp = self.factory.get_system_setting().sysaccount.create_group(group.id)
            elif group.operation == "delete":
                rsp = self.factory.get_system_setting().sysaccount.delete_group(group.id)
            else:
                _logger.error("oepration {} is not permited for groups".format(group.operation))
                continue
            if rsp.success == True:
                _logger.info("Successfully {} group {}".format(group.operation, group.id))
            else:
                _logger.error("Faield to {} group {}:\n{}\n{}".format(
                    group.operation, group.id, json.dumps(group indent=4), rsp.data))

    def account_management(self):
        if config.acount_management != None:
            if config.account_management.groups != None:
                _system_groups(config.account_management.groups)
            if config.account_management.users != None:
                _system_users(config.account_management.users)

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
                role.operation, json.dumps(role, indent=4))

    def management_authorization(self, config):
        if config.management_authorization != None and config.management_authorization.roles != None:
            for role in config.management_authorization.roles:
                _add_auth_role(role)
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

    def date_time(self, config):
        dateTime = self.factory.get_system_setting().date_time
        if config.date_time:
            dtConfig = config.date_time
            rsp =dateTime.update(enable_ntp=dtConfig.enable_ntp, ntp_servers=dtConfig.ntp_servers, 
                    time_zone=dtConfig.time_zone, date_time=dtConfig.date_time)
            if rsp.success == True:
                _logger.info("Successfullt set date/time configuration")
            else:
                _logger.error("Failed to set date/time configuration using:\n{}\n{}".format(
                    json.dumps(dtConfig, indent=4), rsp.content))


    def configure_appliance(self, config, isva_appliance):
        appliance = config.appliance
        admin_config(appliance)
        import_ssl_certificates(appliance)
        account_management(appliance)
        management_authorization(appliance)
        advanced_tuning_parameters(appliance)
        date_time(appliance)
        isva_appliance().configure()


    def configure_container(self, config, isva_container):
        docker = config.docker
        admin_config(docker)
        import_ssl_certificates(docker)
        account_management(docker)
        management_authorization(docker)
        advanced_tuning_parameters(docker)
        isva_container.configure()


    def get_modules(self, config, factory):
        appliance = APPLIANCE(config, factory)
        container = CONTAINER(config, factory)
        web = WEB(config, factory.get_web_settings())
        aac = AAC(config, factory.get_access_control())
        fed = FED(config, factory.get_federation())
        return appliance, container, web, aac, fed


    def configure(self, config_file=None):
        self.config = config_yaml()
        if config_file:
            _logger.info("Reading file from arg {}".format(config_file))
            self.config = data_util.Map( yaml.load( open(config_file, 'r'), data_util.CustomLoader) )
        else if len(config.keys()):
            _logger.info("Reading file from env var ISVA_YAML_CONFIGURATION = {}".format(const.ISVA_CONFIGURATION))
        else:
            raise RuntimeError("Failed to find a YAML configuration file, help!")
        self.factory = pyisva.Factory(mgmt_base_url(), *creds())
        if old_password():
            self.factory = pyisva.Factory(mgmt_base_url(), *old_creds())
            accept_eula(old_creds())
            complete_setup(old_creds())
            set_admin_password(old_creds(), creds())
            self.factory = pyisva.Factory(mgmt_base_url(), *creds())
        else:
            accept_eula(creds())
            complete_setup(creds())
        appliance, container, web, aac, fed = self.get_modules(config, factory)
        if appliance.is_appliance():
            self.configure_appliance(config, appliance)
        elif container.is_container():
            self.configure_container(config, container)
        else:
            _logger.error("Deployment model cannot be found in config.yaml, exiting")
            sys.exit(1)
        activate_appliance()
        web.configure()
        aac.configure()
        fed.configure()

if __name__ == "__main__":
    from isva_configurator import configurator
    configurator.configure()
