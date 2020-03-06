#!/bin/python
import os
import yaml
import logging
from pyisam.factory import Factory
from .util.data_util import Map, CustomLoader

_logger = logging.getLogger(__name__)


HEADERS = {
            "Content-Type":"application/json",
            "Accept":"application/json"
        }


ISVA_CONFIGURATION = os.environ.get("ISVA_CONFIGURATION_YAML")
CONFIG = Map( yaml.load( open(CONFIG_BASE_DIR + ISVA_CONFIGURATION, 'r'), CustomLoader) )
MGMT_BASE_URL = os.environ.get("MGMT_BASE_URL") if os.environ.get("MGMT_BASE_URL") else CONFIG.mgmt_base_url 
CREDS = ("admin", os.environ.get("MGMT_PASSWORD")) if os.environ.get("MGMT_PASSWORD") else ("admin", CONFIG.mgmt_password)
OLD_CREDS = ("admin", os.environ.get("MGMT_OLD_PASSWORD")) if os.environ.get("MGMT_OLD_PASSWORD") else ("admin", CONFIG.mgmt_old_password)
LICENSE_ENDPOINT = MGMT_BASE_URL + "/isam/capabilities/v1"
SETUP_ENDPOINT = MGMT_BASE_URL + "/setup_complete"
EULA_ENDPOINT = MGMT_BASE_URL + "/setup_service_agreements/accepted"

FACTORY = None #Factory(MGMT_BASE_URL, CREDS[0], CREDS[1])
WEB = None #FACTORY.get_web_settings()
AAC = None #FACTORY.get_access_control()
FED = None #FACTORY.get_federation()

KUBERNETES_CLIENT = None
