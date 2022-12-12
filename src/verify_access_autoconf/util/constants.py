#!/bin/python
import os, kubernetes

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

class ISVA_Kube_Client:
    _client = None
    _caught = False

    @classmethod
    def get_client(cls):
        if cls._client == None and cls._caught == False:
            if KUBERNETES_CONFIG in os.environ.keys():
                cls._client = kubernetes.config.load_kube_config(config_file=os.environ.get(KUBERNETES_CONFIG))
            elif cls._caught == False:
                try:
                    cls._client = kubernetes.config.load_config()
                except kubernetes.config.config_exception.ConfigException:
                    cls._caught = True
        print(cls._client)
        return cls._client

KUBE_CLIENT = ISVA_Kube_Client.get_client()
