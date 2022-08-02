#!/bin/bash
export PIP_EXTRA_INDEX_URL="https://${ART_API_USER}:${ART_API_KEY}@na.artifactory.swg-devops.com/artifactory/api/pypi/sec-iam-isam-devops-team-pypi-local/simple"
python setup.py sdist bdist_wheel
export PYTHONPATH="$PYTHONPATH:$(pwd)/build/lib"

python <<EOF
print("Test")
import verify_access_configurator
assert verify_access_configurator.configurator != None
assert verify_access_configurator.appliance != None
assert verify_access_configurator.container != None
assert verify_access_configurator.webseal != None
assert verify_access_configurator.access_control != None
assert verify_access_configurator.federation != None
EOF
