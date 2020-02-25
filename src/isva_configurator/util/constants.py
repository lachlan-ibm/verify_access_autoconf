#!/bin/python
import os
import yaml
import logging
from pyisam.factory import Factory
from isva_util import Map, CustomLoader 

_logger = logging.getLogger(__name__)

CREDS = ("admin", os.environ.get("MGMT_PASSWORD"))

HEADERS = {
            "Content-Type":"application/json",
            "Accept":"application/json"
        }

MGMT_BASE_URL = os.environ.get("MGMT_BASE_URL")
LICENSE_ENDPOINT = MGMT_BASE_URL + "/isam/capabilities/v1"
SETUP_ENDPOINT = MGMT_BASE_URL + "/setup_complete"
EULA_ENDPOINT = MGMT_BASE_URL + "/setup_service_agreements/accepted"

FACTORY = Factory(MGMT_BASE_URL, CREDS[0], CREDS[1])
WEB = FACTORY.get_web_settings()
AAC = FACTORY.get_access_control()
FED = FACTORY.get_federation()

CONFIG_BASE_DIR = os.environ.get("ISVA_CONFIGURATION_AUTOMATION_BASEDIR")
ISVA_CONFIGURATION = os.environ.get("ISVA_CONFIGURATION_YAML")

CONFIG = Map( yaml.load( open(CONFIG_BASE_DIR + ISVA_CONFIGURATION, 'r'), CustomLoader) )

KUBERNETES_CLIENT = None

def update_container_names():
    global KUBERNETES_CLIENT
    #Try update kubernetes containers with generated names
    if CONFIG.docker != None and CONFIG.docker.orchestration == 'kubernetes':
        from kubernetes import client, config
        config.load_kube_config()
        KUBERNETES_CLIENT = client.CoreV1Api()
        pods = []
        ret = KUBERNETES_CLIENT.list_pod_for_all_namespaces(watch=False)
        for e in ret.items:
            if e.metadata.namespace == CONFIG.docker.containers.namespace:
                pods += [e.metadata.name]
        config_pods = []
        webseal_pods = []
        runtime_pods = []
        dsc_pods = []
        for pod in pods:
            if CONFIG.docker.containers.webseal != None and CONFIG.docker.containers.webseal in pod:
                webseal_pods += [pod]
            if CONFIG.docker.containers.runtime != None and CONFIG.docker.containers.runtime in pod:
                runtime_pods += [pod]
            if CONFIG.docker.containers.configuration != None and CONFIG.docker.containers.configuration in pod:
                config_pods += [pod]
            if CONFIG.docker.containers.dsc != None and CONFIG.docker.containers.dsc in pod:
                dsc_pods += [pod]
        CONFIG.docker.containers.configuration = config_pods
        CONFIG.docker.containers.webseal = webseal_pods
        CONFIG.docker.containers.runtime = runtime_pods
        CONFIG.docker.containers.dsc = dsc_pods


def _kube_reload_container(namespace, container):
    from kubernetes.stream import stream
    exec_commands = ['isam_cli', '-c', 'reload', 'all']
    response = stream(KUBERNETES_CLIENT.connect_get_namespaced_pod_exec,
            container,
            namespace,
            command=exec_commands,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False)
    if 'The command completed successfully' in response:
        _logger.info(container + " container reloaded successfully")
    else:
        _logger.error(container + " container failed to reload")

def deploy_pending_changes():
    FACTORY.get_system_settings().configuration.deploy_pending_changes()
    if FACTORY.is_docker() == True and KUBERNETES_CLIENT is not None:
        FACTORY.get_system_settings().docker.publish()
        for container in CONFIG.docker.containers.webseal:
            _kube_reload_container(CONFIG.docker.containers.namespace, container)
        for container in CONFIG.docker.containers.runtime:
            _kube_reload_container(CONFIG.docker.containers.namespace, container)
        for container in CONFIG.docker.containers.dsc:
            _kube_reload_container(CONFIG.docker.containers.namespace, container)

