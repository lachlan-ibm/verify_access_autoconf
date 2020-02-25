#!/bin/python
import sys
import os
import logging
import json
import requests
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

import configure_appliance as isva_appliance
import configure_docker as isva_docker
import configure_aac as aac
import configure_webseal as web
import configure_fed as fed
from  constants import EULA_ENDPOINT, LICENSE_ENDPOINT, SETUP_ENDPOINT, FACTORY, CONFIG, CREDS, HEADERS, CONFIG_BASE_DIR, deploy_pending_changes

_logger = logging.getLogger(__name__)

def accept_eula():
    payload = {"accepted": True}
    rsp = requests.put(EULA_ENDPOINT, auth=CREDS, headers=HEADERS, json=payload, verify=False)
    assert rsp.status_code == 200, "Failed to accept EULA, status code:" + str(rsp.status_code)
    _logger.info("Accepted EULA")


def complete_setup():
    rsp = requests.put(SETUP_ENDPOINT, auth=CREDS, headers=HEADERS, verify=False)
    assert rsp.status_code == 200, "Did not complete setup"
    deploy_pending_changes()
    _logger.info("Completed setup")


def _activateBaseAppliance():
    payload = {'code': CONFIG.appliance.activation.base if CONFIG.appliance else CONFIG.docker.activation.base}
    rsp = requests.post(LICENSE_ENDPOINT, auth=CREDS, headers=HEADERS, json=payload, verify=False)
    assert rsp.status_code == 200, "Could not apply the base license, statuc_code: {}\n{}".format(
            rsp.status_code, rsp.content)
    _logger.info("applied Base licence")

def _activateAdvancedAccessControl():
    payload = {'code': CONFIG.appliance.activation.aac if CONFIG.appliance else CONFIG.docker.activation.aac}
    rsp = requests.post(LICENSE_ENDPOINT, auth=CREDS, headers=HEADERS, json=payload, verify=False)
    assert rsp.status_code == 200, "Could not apply the aac license, statuc_code: {}\n{}".format(
            rsp.status_code, rsp.content)
    _logger.info("applied AAC licence")

def _activateFederation():
    payload = {'code': CONFIG.appliance.activation.fed if CONFIG.appliance else CONFIG.docker.activation.fed}
    rsp = requests.post(LICENSE_ENDPOINT, auth=CREDS, headers=HEADERS, json=payload, verify=False)
    assert rsp.status_code == 200, "Could not apply the fed license, statuc_code: {}/n{}".format(
            rsp.status_code, rsp.content)
    _logger.info("applied Federation licence")

def activate_appliance():
    system = FACTORY.get_system_settings()
    activations = system.licensing.get_activated_modules().json
    if not any(module.get('id', None) == 'wga' and module.get('enabled', "False") == "True" for module in activations):
        _activateBaseAppliance()
    if not any(module.get('id', None) == 'mga' and module.get('enabled', "False") == "True" for module in activations):
        _activateAdvancedAccessControl()
    if not any(module.get('id', None) == 'federation' and module.get('enabled', "False") == "True" for module in activations):
        _activateFederation()
    deploy_pending_changes()
    _logger.info("appliance activated")


def _import_signer_certs(database, base, filePointer):
    ssl = FACTORY.get_system_settings().ssl_certificates
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

def _import_personal_certs(database, base, filePointer):
    ssl = FACTORY.get_system_settings().ssl_certificates
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

def import_ssl_certificates():
    ssl_config = None
    if CONFIG.appliance:
        ssl_config = CONFIG.appliance.ssl_certificates
    elif CONFIG.docker:
        ssl_config = CONFIG.docker.ssl_certificates
    ssl = FACTORY.get_system_settings().ssl_certificates
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


def configure():
    if CONFIG_BASE_DIR == None:
        _logger.error("Must set env varibale \"CONFIG_BASE_DIR\"." 
                " This should be the absolute path the configuration files required to set up ISVA")
    accept_eula()
    complete_setup()
    import_ssl_certificates()
    if CONFIG.appliance != None:
        isva_appliance.configure()
    elif CONFIG.docker != None:
        isva_docker.configure()
    else:
        _logger.error("Deployment model cannot be found in config.yaml, exiting")
        sys.exit(1)
    activate_appliance()
    web.configure()
    aac.configure()
    fed.configure()

if __name__ == "__main__":
    configure()
