#!/bin/python
import os, kubernetes
import .constants as const


def config_base_dir():
    if const.CONFIG_BASE_DIR in os.environ.keys():
        return os.environ.get(const.CONFIG_BASE_DIR)
    return os.path.expanduser("~") #Default is home directory


def config_yaml():
    if const.CONFIG_YAML_ENV_VAR in os.environ.keys():
        return Map(yaml.load(
            os.environ.get(const.CONFIG_YAML_ENV_VAR), 'r'), data_util.CustomLoader)
    elif config_base_dir() and const.CONFIG_YAML in os.lsdir(config_base_dir()):
        return Map(yaml.load(
            os.path.join(config_base_dir(), const.CONFIG_YAML), 'r'), data_util.CustomLoader)
    else:
        return Map()


def mgmt_base_url():
    return os.environ.get(const.MGMT_BASE_URL_ENV_VAR, "https://localhost")

def creds():
    if const.MGMT_USER_ENV_VAR in os.environ.keys():
        return (os.environ.get(const.MGMT_USER_ENV_VAR, "admin"), 
                    os.environ.get(const.MGMT_PWD_ENV_VAR, "admin"))
    else:
        cfg = config_yaml()
        return (cfg.mgmt_user, cfg.mgmt_pwd)


def old_creds():
    if const.MGMT_OLD_PASSWORD_ENV_VAR in os.environ.keys():
        return (os.environ.get(const.MGMT_USER_ENV_VAR, "admin"), 
                    os.environ.get(const.MGMT_OLD_PASSWORD_ENV_VAR, "admin"))
    else:
        mgmtUser = creds()(0)
        oldPwd = config_yaml().mgmt_old_pwd
        return (mgmtUser, oldPwd)


def update_container_names(isvaConfig):
    #Try update kubernetes containers with generated names
    if isvaConfig.docker != None and isvaConfig.docker.orchestration == 'kubernetes':
        kubernetes_config = os.environ.get(const.KUBERNETES_CONFIG) #If none config will be loaded from default location
        kubernetes.config.load_kube_config(config_file=kubernetes_config)
        kubeClient = kubernetes.client.CoreV1Api()
        pods = []
        ret = kubeClient.list_pod_for_all_namespaces(watch=False)
        for e in ret.items:
            if e.metadata.namespace == isvaConfig.docker.containers.namespace:
                pods += [e.metadata.name]
        config_pods = []
        webseal_pods = []
        runtime_pods = []
        dsc_pods = []
        for pod in pods:
            if isvaConfig.docker.containers.webseal != None and isinstance( isvaConfig.docker.containers.webseal, str):
                if isvaConfig.docker.containers.webseal in pod:
                    webseal_pods += [pod]
            if isvaConfig.docker.containers.runtime != None and isinstance( isvaConfig.docker.containers.runtime, str):
                if isvaConfig.docker.containers.runtime in pod:
                    runtime_pods += [pod]
            if isvaConfig.docker.containers.configuration != None and isinstance( isvaConfig.docker.containers.configuration, str):
                if isvaConfig.docker.containers.configuration in pod:
                    config_pods += [pod]
            if isvaConfig.docker.containers.dsc != None and isinstance( isvaConfig.docker.containers.dsc, str):
                if isvaConfig.docker.containers.dsc in pod:
                    dsc_pods += [pod]
        if config_pods:
            isvaConfig.docker.containers.configuration = config_pods
        if webseal_pods:
            isvaConfig.docker.containers.webseal = webseal_pods
        if runtime_pods:
            isvaConfig.docker.containers.runtime = runtime_pods
        if dsc_pods:
            isvaConfig.docker.containers.dsc = dsc_pods


def _kube_reload_container(client, namespace, container):
    from kubernetes.stream import stream
    exec_commands = ['isam_cli', '-c', 'reload', 'all']
    response = stream(client.connect_get_namespaced_pod_exec,
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


def _kube_rollout_restart(client, namespace, deployment):
    #TODO
    return

def _get_kube_client():
    #TODO
    return

def deploy_pending_changes(factory=None, isvaConfig=None):
    if not factory:
        factory = pyisva.Factory(mgmt_base_url(), *creds())
    factory.get_system_settings().configuration.deploy_pending_changes()
    kube_client = _get_kube_client()
    if factory.is_docker() == True and kube_client is not None:
        namespace = isvaConfig.docker.containers.namespace
        factory.get_system_settings().docker.publish()
        for container in isvaConfig.docker.containers.webseal:
            _kube_reload_container(kube_client, namespace, container)
        for container in isvaConfig.docker.containers.runtime:
            _kube_reload_container(kube_client, namespace, container)
        for container in isvaConfig.docker.containers.dsc:
            _kube_reload_container(kube_client, namespace, container)
