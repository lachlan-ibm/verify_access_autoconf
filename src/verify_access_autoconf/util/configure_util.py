#!/bin/python
import os, kubernetes, logging, sys, yaml, pyisva, datetime, subprocess, shutil
from . import constants as const
from .data_util import Map, FileLoader, CustomLoader
from kubernetes.stream import stream

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
_logger = logging.getLogger(__name__)

def config_base_dir():
    if const.CONFIG_BASE_DIR in os.environ.keys():
        return os.environ.get(const.CONFIG_BASE_DIR)
    return os.path.expanduser("~") #Default is home directory


def config_yaml(config_file=None):
    if config_file:
        _logger.info("Reading file from provided path {}".format(config_file))
        config = data_util.Map(yaml.load(open(config_file, 'r'), Loader=CustomLoader))
    elif const.CONFIG_YAML_ENV_VAR in os.environ.keys():
        _logger.info("Reading file from env var {} = {}".format(
            const.CONFIG_YAML_ENV_VAR, os.environ.get(const.CONFIG_YAML_ENV_VAR)))
        return Map(yaml.load(open(
            os.environ.get(const.CONFIG_YAML_ENV_VAR), 'r'), Loader=CustomLoader))
    elif config_base_dir() and const.CONFIG_YAML in os.listdir(config_base_dir()):
        _logger.info("Reading config file from {} env var: {}/config.yaml".format(
            const.CONFIG_BASE_DIR, os.environ.get(const.CONFIG_BASE_DIR)))
        return Map(yaml.load(open(
            os.path.join(config_base_dir(), const.CONFIG_YAML), 'r'), Loader=CustomLoader))
    else:
        raise RuntimeError("Failed to find a YAML configuration file, help!")


def read_files(base):
    contents = []
    if base.startswith("/"):
        contents = FileLoader("").read_files(base.lstrip("/"))
    else:
        contents = FileLoaser(config_base_dir()).read_files(base)
    return contents


def read_file(fp):
    contents = None
    if fp.startswith("/"):
        contents = FileLoaser("").read_file(fp.lstrip('/'))
    else:
        contents = FileLoader(config_base_dir()).read_file(fp)
    return contents


def mgmt_base_url(cfg=None):
    if cfg == None:
        cfg = config_yaml()
    return os.environ.get(const.MGMT_URL_ENV_VAR, cfg.mgmt_base_url)

def creds(cfg=None):
    user = None
    secret = None
    if const.MGMT_USER_ENV_VAR in os.environ.keys():
        user = os.environ.get(const.MGMT_USER_ENV_VAR)
    if const.MGMT_PWD_ENV_VAR in os.environ.keys():
        secret = os.environ.get(const.MGMT_PWD_ENV_VAR)
    if user == None or secret == None:
        if cfg == None:
            cfg = config_yaml()
        if user == None:
            user = cfg.get('mgmt_user', "admin")
        if secret == None:
            secret = cfg.get('mgmt_pwd', "admin")
    return (user, secret)


def old_creds(cfg=None):
    user = None
    secret = None
    if const.MGMT_OLD_PASSWORD_ENV_VAR in os.environ.keys():
        user = os.environ.get(const.MGMT_USER_ENV_VAR)
    if const.MGMT_OLD_PASSWORD_ENV_VAR in os.environ.keys():
        secret = os.environ.get(const.MGMT_OLD_PASSWORD_ENV_VAR)
    if user == None or secret == None:
        if user == None:
            user = cfg.get('mgmt_user', "admin")
        if secret == None:
            secret = cfg.get('mgmt_old_pwd', "admin")
    return (user, secret)


def _kube_reload_container(client, namespace, container):
    exec_commands = ['isam_cli', '-c', 'reload', 'all']
    response = stream(client.CoreV1Api().connect_get_namespaced_pod_exec,
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
    now = datetime.datetime.utcnow()
    now = str(now.isoformat("T") + "Z")
    body = {
        'spec': {
            'template':{
                'metadata': {
                    'annotations': {
                        'kubectl.kubernetes.io/restartedAt': now
                    }
                }
            }
        }
    }
    try:
        client.AppsV1Api().patch_namespaced_deployment(deployment, namespace, body, pretty='true')
    except kubernetes.client.rest.ApiException as e:
        _logger.error("Exception when calling AppsV1Api->patch_namespaced_deployment: %s\n" % e)
        sys.exit(1)
    return

def _compose_restart_container(container, config):
    if shutil.which("docker-compose") == None:
        _logger.error("docker-compose not found on $PATH")
        sys.exit(1)
    composeYaml = None
    if const.DOCKER_COMPOSE_CONFIG in os.environ.keys():
        composeYaml = os.environ.get(const.DOCKER_COMPOSE_CONFIG)
    elif config.containers.docker_compose_yaml is not None:
        composeYaml = config.containers.docker_compose_yaml
    else:
        _logger.error("Unable to find docekr-compose YAML configuration")
        sys.exit(1)
    ps = subprocess.run(['docker-compose', '-f' , composeYaml, 'restart', container])
    if ps.returncode != 0:
        _logger.error("Error restarting docker-compose container:\nstdout: {}\nstderr{}".format(ps.stdout, ps.stderr))
        sys.exit(1)

def deploy_pending_changes(factory=None, isvaConfig=None):
    if not isvaConfig:
        isvaConfig = config_yaml()
    if not factory:
        factory = pyisva.Factory(mgmt_base_url(isvaConfig), *creds(isvaConfig))

    factory.get_system_settings().configuration.deploy_pending_changes()
    if factory.isDocker() == True and isvaConfig.container is not None:
        #We know about containers and have a k8s client that can control them
        factory.get_system_settings().docker.publish()
        kube_client = const.KUBE_CLIENT.get_client()

        if isvaConfig.container.orchestration == "kubernetes":
            #Are we restarting the containers or rolling out a restard to the deployment descriptor
            if isvaConfig.container.k8s_deployments is not None:
                namespace = isvaConfig.docker.container.k8s_deployment.namespace
                for deployment in isvaConfig.docker.k8s_deployments.webseal:
                    _kube_rollout_restart(kube_client, namespace, deployment)
                for deployment in isvaConfig.docker.k8s_deployments.runtime:
                    _kube_rollout_restart(kube_client, namespace, deployment)
                for deployment in isvaConfig.docker.k8s_deployments.dsc:
                    _kube_rollout_restart(kube_client, namespace, deployment)

            if isvaConfig.container.pods is not None:
                for pod in isvaConfig.container.pods:
                    _kube_restart_container(kube_client, namespace, pod)

        elif isvaConfig.container.orchestration == "docker-compose":
            for container in isvaConfig.docker.container.compose_containers:
                _compose_restart_container(container, isvaConfig)
        elif isvaConfig.container.orchestration == "docker":
            #TODO
            pass
        else:
            _logger.error("Unable to perform container restart, this may lead to errors")

