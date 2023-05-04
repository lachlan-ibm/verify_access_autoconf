# IBM Security Verify Access Configuration Automation
This repository is used to configure IBM Security Verify Access (ISVA) using a yaml file of the required configuration. 

This project aims to be idempotent, ie if the configuration is run multiple times on the same appliance it should not break and should pick up any configuration changes in the yaml configuration file.

## Example deployments
To get started several example deployments are available in the [Examples](examples/) directory. The example yaml files must be updated with deployment specific parameters, usually this is network addresses and ISVA activation codes.

# Setup
## Environment
- `ISVA_CONFIG_BASE` = directory which contains the YAML configuration file as well as any http template pages, PKI, mapping rules, ect.
- `ISVA_CONFIG_YAML` = path to ISVA configuration yaml file. Path should be relative to `ISVA_CONFIG_BASE`
- `ISVA_MGMT_BASE_URL` = address to access ISVA LMI, eg. https://\<isva appliance\>:\<isva port\>. This property can also be specified in the configuration yaml file. If present, this property will take precedence.
- `ISVA_MGMT_USER` = The user to perform configuration as. If not supplied the `admin` user is used.
- `ISVA_MGMT_PWD` = administrator password for the administrator account performing configuration. This property can also be specified in the configuration yaml file. If present, this property will take precedence.
- `ISVA_MGMT_OLD_PWD` = if a password change for the administrator account (eg. from the default) is required, the old password can be specified with this environment variable. If present the administrator's password will be changed from `MGMT_OLD_PASSWORD` to `MGMT_PASSWORD`
- `ISVA_KUBERNETES_YAML_CONFIG` (optional) = path to Kubernetes configuration yaml for kubernetes deployments. 
  - Note: If your kubernetes cluster requires mutual authentication (TLS) then a pem certificate file must also be available to ISVA Configurator
  - Note: When run from a Kubernetes cluster a Service Account can be used in place of a YAML configuration file

## Deployment
### Local environment
IBM Security Verify Access Configuration Automation is simple to run locally. 
1. First the required python packages are installed from [PyPi](https://pypi.org/project/verify-access-autoconf/). 
2. Set the required environment variables
3. a python interactive shell or python script can be used to configure appliances:
```python
>>> import verify_access_autoconf
>>> verify_access_autoconf.configurator.configure()
```

### Docker
IBM Security Verify Access Automated Configurator can also be run within a docker container. Use to [Dockerfile](Dockerfile) to build a local docker image.

The docker container can be built and run with the following command executed from the top level directory of the configurator source code. When starting the container the required environment variables must be set and the docker container must be able to route to the ISVA appliances/containers which are to be configured.

```
docker build --no-cache --force-rm -t verify-access-configurator .

docker run --volume /path/to/config/yaml:/config --env "ISVA_CONFIGURATION_BASE_DIR=/config" --env ISVA_MGMT_BASE_URL="https://<mgmt address>:<mgmt port>" --env "ISVA_MGMT_PASSWORD=Passw0rd1!" verify-access-configurator
```


### Kubernetes
IBM Security Verify Access Automated Configurator can be run from within a Kubernetes cluster. This is useful if there are routing issues between the deployment host and the kubernetes external addresses this option will allow for configuration using the kubernetes internal network.

Here is an example Kubernetes batch" object which deploys a container to apply a configuration to a cluster.
> note This requires a user to create the `verify-config` ConfigMap object with the required configuration files plus any additional Secrets which are referenced.

```
apiVersion: batch/v1
kind: Job
metadata:
  name: verify-access-configurator
spec:
  template:
    spec:
      containers:
      - name: verify-access-configurator
        image: python3:latest
        command: ["python3", "-m", "verify_access_autoconf"]
        volumeMounts:
        - name: verify-access-config
          mountPath: /verify_access_config
        env:
        - name: ISVA_CONFIG_BASE
          value: "/verify_access_config"
        - name: ISVA_MGMT_BASE_URL
          value: "https://isamconfig:9443"
        - name: ISVA_MGMT_PASSWORD
          value: "Passw0rd1!"
        - name: ISVA_CONFIGURATOR_LOG_LEVEL
          value: "ALL"
      restartPolicy: Never
      volumes:
      - name: verify-access-config
        configMap:
          name: verify-access-config
      initContainers:
        - name: install-verify-access-autoconf
          image: python3:latest
          command: ["bash", "-c", "pip3 install verify-access-autoconf"]
  backoffLimit: 4
```

## Documentation
Documentation for using this library can be found on [Verify Access Automated Configurator's GitHub pages](https://lachlan-ibm.github.io/verify-access-autoconf/index.html).
