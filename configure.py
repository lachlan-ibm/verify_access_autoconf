#!/bin/bash
import os
import logging
import requests

from . import configure_aac as aac
from . import configure_webseal as web
from . import configure_fed as fed
from . import constants as const


_logger = logging.getLogger(__name__)

def accept_eula():
    payload = {"accepted": True}
    rsp = requests.put(const.MGMT_BASE_URL + "/setup_service_agreements/accepted", 
            auth=const.CREDS, headers=const.HEADERS, json=payload, verify=False)
    assert rsp.status_code == 200, "Failed to accept EULA, status code:" + str(rsp.status_code)
    _logger.info("Accepted EULA")


def complete_setup():
    rsp = requests.put(const.MGMT_BASE_URL + "/setup_complete", 
            auth=const.CREDS, headers=const.HEADERS, verify=False)
    assert rsp.status_code == 200, "Did not complete setup"
    deployPendingChanges()
    _logger.info("Completed setup")


def _activateBaseAppliance(release):
    payload = {'code': const.BASE_CODE}
    rsp = requests.post(const.MGMT_BASE_URL + "/isam/capabilities/v1", 
            auth=const.CREDS, headers=const.HEADERS, json=payload, verify=False)
    assert rsp.status_code == 200, "Could not apply the base license, statuc_code: " + str(rsp.status_code)
    _logger.info("applied Base licence")

def _activateAdvancedAccessControl(release):
    payload = {'code': const.AAC_CODE}
    rsp = requests.post(const.MGMT_BASE_URL + "/isam/capabilities/v1", 
            auth=const.CREDS, headers=const.HEADERS, json=payload, verify=False)
    assert rsp.status_code == 200, "Could not apply the base license, statuc_code: " + str(rsp.status_code)
    _logger.info("applied AAC licence")

def _activateFederation(release):
    payload = {'code': const.FED_CODE}
    rsp = requests.post(const.MGMT_BASE_URL + "/isam/capabilities/v1", 
            auth=const.CREDS, headers=const.HEADERS, json=payload, verify=False)
    assert rsp.status_code == 200, "Could not apply the base license, statuc_code: " + str(rsp.status_code)
    _logger.info("applied Federation licence")


def activate_appliance():
    _activateBaseAppliance()
    _activateAdvancedAccessControl()
    _activateFederation()
    const.deployPendingChanges()
    _logger.info("appliance activated")


def first_steps():
    accept_eula()
    complete_setup()
    activate_appliance()


def configure():
    web.configure()
    aac.configure()
    fed.configure()

if __name__ = "__main__":
    if CONFIG_BASE_DIR == None:
        _logger.error("Must set env varibale \"CONFIG_BASE_DIR\"." \ 
                " This should be the absolute path the configuration files required to set up ISVA")

    first_steps()
    configure()
