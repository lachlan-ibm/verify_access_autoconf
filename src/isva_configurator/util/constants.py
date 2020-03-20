#!/bin/python
import os
import yaml
from pyisam.factory import Factory
from .data_util import Map, CustomLoader


HEADERS = {
            "Content-Type":"application/json",
            "Accept":"application/json"
        }


ISVA_CONFIGURATION = os.environ.get("ISVA_CONFIGURATION_YAML")
CONFIG_BASE_DIR = os.environ.get("ISVA_CONFIGURATION_BASE_DIR")
CONFIG = Map( yaml.load( open(ISVA_CONFIGURATION, 'r'), CustomLoader) ) if ISVA_CONFIGURATION else None
MGMT_BASE_URL = os.environ.get("MGMT_BASE_URL") 
if not MGMT_BASE_URL and CONFIG:
    MGMT_BASE_URL = CONFIG.mgmt_base_url
CREDS = ("admin", os.environ.get("MGMT_PASSWORD")) if os.environ.get("MGMT_PASSWORD") else None
if not CREDS and CONFIG:
    CREDS = ("admin", CONFIG.mgmt_password)
OLD_CREDS = ("admin", os.environ.get("MGMT_OLD_PASSWORD")) if os.environ.get("MGMT_OLD_PASSWORD") else None
if not OLD_CREDS and CONFIG and CONFIG.mgmt_old_password:
    OLD_CREDS = ("admin", CONFIG.mgmt_old_password)

FACTORY = None #Factory(MGMT_BASE_URL, CREDS[0], CREDS[1])
WEB = None #FACTORY.get_web_settings()
AAC = None #FACTORY.get_access_control()
FED = None #FACTORY.get_federation()

KUBERNETES_CLIENT = None
