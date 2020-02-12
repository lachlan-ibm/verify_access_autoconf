#!/bin/sh

export ISVA_CONFIGURATION_AUTOMATION_BASEDIR=/home/lowkey/git.workspace/ISVAConfigurationAutomation

if [ -z "${ISVA_CONFIGURATION_AUTOMATION_BASEDIR}" ]; then
    read -p "ISVA Configuration Automation base directory [$(pwd)]: " ISVA_CONFIGURATION_AUTOMATION_BASEDIR
    if [ -z "${ISVA_CONFIGURATION_AUTOMATION_BASEDIR}" ]; then
        ISVA_CONFIGURATION_AUTOMATION_BASEDIR="$(pwd)"
    fi
    export ISVA_CONFIGURATION_AUTOMATION_BASEDIR="${ISVA_CONFIGURATION_AUTOMATION_BASEDIR}"
fi

if [ ! -f "${ISVA_CONFIGURATION_AUTOMATION_BASEDIR}/config.yaml" ]; then
    echo "Must define a cofiguration file @ ${ISVA_CONFIGURATION_AUTOMATION_BASEDIR}/config.yaml"
    exit 1
fi

export PYTHONPATH="${PYTHONPATH}:${ISVA_CONFIGURATION_AUTOMATION_BASEDIR}/pyisam:${ISVA_CONFIGURATION_AUTOMATION_BASEDIR}/src"

if [ -z "$MGMT_BASE_URL" ]; then
    read -p "Management base url: " MGMT_BASE_URL
    export MGMT_BASE_URL="${MGMT_BASE_URL}"
fi

if [ -z "$MGMT_PASSWORD" ]; then
    read -p "Management adminitration password [\"admin\"]: " MGMT_PASSWORD
    if [ -z "${MGMT_PASSWORD}" ]; then
        MGMT_PASSWORD="admin"
    fi
    export MGMT_PASSWORD="${MGMT_PASSWORD}"
fi

python3 src/configure.py
