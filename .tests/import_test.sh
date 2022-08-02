#!/bin/bash
export PIP_EXTRA_INDEX_URL="https://${ART_API_USER}:${ART_API_KEY}@na.artifactory.swg-devops.com/artifactory/api/pypi/sec-iam-isam-devops-team-pypi-local/simple"
python setup.py sdist bdist_wheel
export PYTHONPATH="$PYTHONPATH:$(pwd)/build/lib"

python <<EOF
print("Test")
import verify-access-autoconf
assert verify-access-autoconf.configurator != None
assert verify-access-autoconf.appliance != None
assert verify-access-autoconf.container != None
assert verify-access-autoconf.webseal != None
assert verify-access-autoconf.access_control != None
assert verify-access-autoconf.federation != None
EOF
