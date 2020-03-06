#!/bin/python
import os
from kubernetes import client, config

import .util.constants as const

def update_container_names():
    #Try update kubernetes containers with generated names
    if const.CONFIG.docker != None and const.CONFIG.docker.orchestration == 'kubernetes':
        kubernetes_config = os.environ.get("ISVA_KUBERNETES_CONFIG") #If none config will be loaded from default location
        config.load_kube_config(config_file=kubernetes_config)
        const.KUBERNETES_CLIENT = client.CoreV1Api()
        pods = []
        ret = const.KUBERNETES_CLIENT.list_pod_for_all_namespaces(watch=False)
        for e in ret.items:
            if e.metadata.namespace == const.CONFIG.docker.containers.namespace:
                pods += [e.metadata.name]
        config_pods = []
        webseal_pods = []
        runtime_pods = []
        dsc_pods = []
        for pod in pods:
            if const.CONFIG.docker.containers.webseal != None and isinstance( const.CONFIG.docker.containers.webseal, str):
                if const.CONFIG.docker.containers.webseal in pod:
                    webseal_pods += [pod]
            if const.CONFIG.docker.containers.runtime != None and isinstance( const.CONFIG.docker.containers.runtime, str):
                if const.CONFIG.docker.containers.runtime in pod:
                    runtime_pods += [pod]
            if const.CONFIG.docker.containers.configuration != None and isinstance( const.CONFIG.docker.containers.configuration, str):
                if const.CONFIG.docker.containers.configuration in pod:
                    config_pods += [pod]
            if const.CONFIG.docker.containers.dsc != None and isinstance( const.CONFIG.docker.containers.dsc, str):
                if const.CONFIG.docker.containers.dsc in pod:
                    dsc_pods += [pod]
        if config_pods:
            const.CONFIG.docker.containers.configuration = config_pods
        if webseal_pods:
            const.CONFIG.docker.containers.webseal = webseal_pods
        if runtime_pods:
            const.CONFIG.docker.containers.runtime = runtime_pods
        if dsc_pods:
            const.CONFIG.docker.containers.dsc = dsc_pods


def _kube_reload_container(namespace, container):
    from kubernetes.stream import stream
    exec_commands = ['isam_cli', '-c', 'reload', 'all']
    response = stream(const.KUBERNETES_CLIENT.connect_get_namespaced_pod_exec,
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
    const.FACTORY.get_system_settings().configuration.deploy_pending_changes()
    if const.FACTORY.is_docker() == True and const.KUBERNETES_CLIENT is not None:
        namespace = const.CONFIG.docker.containers.namespace
        FACTORY.get_system_settings().docker.publish()
        for container in const.CONFIG.docker.containers.webseal:
            _kube_reload_container(namespace, container)
        for container in const.CONFIG.docker.containers.runtime:
            _kube_reload_container(namespace, container)
        for container in const.CONFIG.docker.containers.dsc:
            _kube_reload_container(namespace, container)
