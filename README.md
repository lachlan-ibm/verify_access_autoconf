# IBM Security Verify Access Configuration Automation
This repository is used to configure IBM Security Verify Access (ISVA) using a yaml file of the required configuration. 

This project aims to be idempotent, ie if the configuration is run multiple times on the same appliance it should not break and should pick up any configuration changes in the yaml configuration file.

## Example deployments
To get started several example deployments are avaliable in the [Examples](examples/) directory. The example yaml files must be updated with deployment specific parameters, usually this is network addresses and ISVA activation codes.

# Setup
### Environment

- `ISVA_CONFIGURATION_BASEDIR` = base directory which constains ISVA Configurator source code
- `ISVA_CONFIGURATION` = path to ISVA configuration yaml file. Path should be relative to `ISVA_CONFIGURATION_BASEDIR`
- `MGMT_BASE_URL` = address to access ISVA LMI, eg. https://\<isva appliance\>:\<isva port\>
- `MGMT_PASSWORD` = administrator password for the `admin` account
- `KUBECONFIG` (optional) = path to Kubernetes configuration yaml for kubernetes deployments. Path should be relative to `ISVA_CONFIGURATION_BASEDIR`. Note that if your kubernetes cluster requires mutual authentication (TLS) then a pem certificate file must also be avaliable to ISVA Configurator

##Deployment
## Local environment
IBM Security Verify Access Configuration Automation is simple to run locally. after setting the required environment variables use python to run `src/configure.py`. `deploy.sh` is an example of this deployment option.

## Docker
IBM Security Verify Access Configuration Automation can also be run within a docker container. Use to [Dockerfile](Dockerfile) to build a local docer image or pull the latest image from [ISVA Devops Artifactory](https://na.artifactory.swg-devops.com/artifactory/sec-iam-isam-devops-team-docker-local/)\(IBM w3 login is required\).

When starting the container the required environment variables must be set and the docker container must be able to route to the ISVA appliances/containers which are to be configured.

An example docker run command is:
`docker run -it --rm --volume /path/to/kubernetes/config.yaml:/root/kube-config.yaml --volume /path/to/kubernetes/ssl.pem:/root/ssl.pem --env KUBECONFIG='/root/kube-config.yaml' --env MGMT_BASE_URL='https://<mgmt address>:<mgmt port>' --env MGMT_PASSWORD='admin' sec-iam-isam-devops-team-docker-local.artifactory.swg-devops.com/isva-configurator`

## Kubernetes
ISVA Configurator can also be run from within a Kubernetes cluster. This is useful if there are routing issues between the deployment host and the kubernetes external addresses this option will allow for configuration using the kubernetes internal network.

