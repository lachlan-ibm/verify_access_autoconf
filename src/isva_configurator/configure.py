#!/bin/python
import sys
import os
import logging
import json
import requests
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

from .appliance.configure_appliance import Appliance_Configurator as isva_appliance
from .docker.configure_docker import Docker_Configurator as isva_docker
from .access_control.configure_aac import AAC_Configurator as aac
from .webseal.configure_webseal import WEAB_Configurator as web
from .federation.configure_fed import FED_Configurator as fed
from  .util.constants import EULA_ENDPOINT, LICENSE_ENDPOINT, SETUP_ENDPOINT, CONFIG, CREDS, OLD_CREDS, HEADERS, CONFIG_BASE_DIR, MGMT_BASE_URL
from .util import constants as const
from .util.configure_util import deploy_pending_changes

_logger = logging.getLogger(__name__)

class ISVA_Configurator(object):

    def old_password(self):
        rsp = requests.get(MGMT_BASE_URL, auth=OLD_CREDS, headers=HEADERS, verify=False)
        if rsp.status_code == 403:
            return False
        return True


    def set_admin_password(self, old, new):
        pass


    def accept_eula(self, creds):
        payload = {"accepted": True}
        rsp = requests.put(EULA_ENDPOINT, auth=creds, headers=HEADERS, json=payload, verify=False)
        assert rsp.status_code == 200, "Failed to accept EULA, status code:" + str(rsp.status_code)
        _logger.info("Accepted EULA")


    def complete_setup(self, creds):
        rsp = requests.put(SETUP_ENDPOINT, auth=creds, headers=HEADERS, verify=False)
        assert rsp.status_code == 200, "Did not complete setup"
        deploy_pending_changes()
        _logger.info("Completed setup")


    def _activateBaseAppliance(self):
        payload = {'code': CONFIG.appliance.activation.base if CONFIG.appliance else CONFIG.docker.activation.base}
        rsp = requests.post(LICENSE_ENDPOINT, auth=CREDS, headers=HEADERS, json=payload, verify=False)
        assert rsp.status_code == 200, "Could not apply the base license, statuc_code: {}\n{}".format(
                rsp.status_code, rsp.content)
        _logger.info("applied Base licence")

    def _activateAdvancedAccessControl(self):
        payload = {'code': CONFIG.appliance.activation.aac if CONFIG.appliance else CONFIG.docker.activation.aac}
        rsp = requests.post(LICENSE_ENDPOINT, auth=CREDS, headers=HEADERS, json=payload, verify=False)
        assert rsp.status_code == 200, "Could not apply the aac license, statuc_code: {}\n{}".format(
                rsp.status_code, rsp.content)
        _logger.info("applied AAC licence")

    def _activateFederation(self):
        payload = {'code': CONFIG.appliance.activation.fed if CONFIG.appliance else CONFIG.docker.activation.fed}
        rsp = requests.post(LICENSE_ENDPOINT, auth=CREDS, headers=HEADERS, json=payload, verify=False)
        assert rsp.status_code == 200, "Could not apply the fed license, statuc_code: {}/n{}".format(
                rsp.status_code, rsp.content)
        _logger.info("applied Federation licence")

    def activate_appliance(self):
        system = const.FACTORY.get_system_settings()
        activations = system.licensing.get_activated_modules().json
        if not any(module.get('id', None) == 'wga' and module.get('enabled', "False") == "True" for module in activations):
            _activateBaseAppliance()
        if not any(module.get('id', None) == 'mga' and module.get('enabled', "False") == "True" for module in activations):
            _activateAdvancedAccessControl()
        if not any(module.get('id', None) == 'federation' and module.get('enabled', "False") == "True" for module in activations):
            _activateFederation()
        deploy_pending_changes()
        _logger.info("appliance activated")


    def _import_signer_certs(self, database, base, filePointer):
        ssl = const.FACTORY.get_system_settings().ssl_certificates
        base = base if base.endswith('/') else base + '/'
        if os.path.isdir(base + filePointer):
            for fp in os.listdir(base + filePointer):
                _import_signer_certs(database, base + filePointer, fp)
        elif os.path.isfile(base + filePointer):
            rsp = ssl.import_signer(database, os.path.abspath(base + filePointer), label=filePointer)
            if rsp.success == True:
                _logger.info("Successfully uploaded {} signer certificate to {}".format(
                    filePointer, database))
            else:
                _logger.error("Failed to upload {} signer certificate to {} database\n{}".format(
                    filePointer, database, rsp.data))

    def _import_personal_certs(self, database, base, filePointer):
        ssl = const.FACTORY.get_system_settings().ssl_certificates
        base = base if base.endswith('/') else base + '/'
        if os.path.isdir(base + filePointer):
            for fp in os.listdir(base + filePointer):
                _import_personal_certs(database, base + filePointer, fp)
        elif os.path.isfile(base + filePointer):
            rsp = ssl.import_personal(database, os.path.abspath(base + filePointer))
            if rsp.success == True:
                _logger.info("Successfully uploaded {} personal certificate to {}".format(
                    filePointer, database))
            else:
                _logger.error("Failed to upload {} personal certificate to {}/n{}".format(
                    filePointer, database, rsp.data))

    def import_ssl_certificates(self):
        ssl_config = None
        if CONFIG.appliance:
            ssl_config = CONFIG.appliance.ssl_certificates
        elif CONFIG.docker:
            ssl_config = CONFIG.docker.ssl_certificates
        ssl = const.FACTORY.get_system_settings().ssl_certificates
        base_dir = CONFIG_BASE_DIR if CONFIG_BASE_DIR.endswith('/') else CONFIG_BASE_DIR + '/'
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
                        _import_signer_certs(database.name, base_dir, fp)
                if database.personal_certificates:
                    for fp in database.personal_certificates:
                        _import_personal_certs(database.name, base_dir, fp)
        deploy_pending_changes()


    def configure(self, config_file=None):
        if config_file:
            from .util import constants, data_util
            import yaml
            constants.CONFIG = data_util.Map( yaml.load( open(config_file, 'r'), data_util.CustomLoader) )
        if old_password():
            const.FACTORY = pyisam.Factory(MGMT_BASE_URL, OLD_CREDS[0], OLD_CREDS[1])
            accept_eula(OLD_CREDS)
            complete_setup(OLD_CREDS)
            set_admin_password(OLD_CREDS, CREDS)
        else:
            const.FACTORY = pyisam.Factory(MGMT_BASE_URL, CREDS[0], CREDS[1])
            accept_eula(CREDS)
            complete_setup(CREDS)
        const.FACTORY = pyisam.Factory(MGMT_BASE_URL, CREDS[0], CREDS[1])
        const.WEB = const.FACTORY.get_web_settings()
        const.AAC = const.FACTORY.get_access_control()
        const.FED = const.FACTORY.get_federation()
        import_ssl_certificates()
        if CONFIG.appliance != None:
            isva_appliance().configure()
        elif CONFIG.docker != None:
            isva_docker().configure()
        else:
            _logger.error("Deployment model cannot be found in config.yaml, exiting")
            sys.exit(1)
        activate_appliance()
        web().configure()
        aac().configure()
        fed().configure()

if __name__ == "__main__":
    from isva_configurator import configurator
    configurator.configure()
