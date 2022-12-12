#!/bin/python

HEADERS = {
            "Content-Type":"application/json",
            "Accept":"application/json"
        }

API_HEADERS = {
            "Content-Type":"application/json",
            "Accept":"application/json"
        }

CONFIG_YAML_ENV_VAR = "ISVA_CONFIG_YAML"

CONFIG_YAML = "config.yaml"

CONFIG_BASE_DIR = "ISVA_CONFIG_BASE"

KUBERNETES_CONFIG = "ISVA_KUBERNETES_YAML_CONFIG"

DOCKER_COMPOSE_CONFIG = "ISVA_DOCEKR_COMPOSE_CONFIG"

MGMT_USER_ENV_VAR = "ISVA_MGMT_USER"

MGMT_PWD_ENV_VAR = "ISVA_MGMT_PWD"

MGMT_URL_ENV_VAR = "ISVA_MGMT_BASE_URL"

MGMT_OLD_PASSWORD_ENV_VAR = "ISVA_MGMT_OLD_PWD"

LOG_LEVEL = "ISVA_CONFIGURATOR_LOG_LEVEL"
