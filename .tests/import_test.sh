#!/bin/bash
export PIP_EXTRA_INDEX_URL="https://${ART_API_USER}:${ART_API_KEY}@na.artifactory.swg-devops.com/artifactory/api/pypi/sec-iam-isam-devops-team-pypi-local/simple"
pip install -r dev-requirements.txt
python setup.py sdist bdist_wheel
export PYTHONPATH="$PYTHONPATH:$(pwd)/build/lib"

python <<EOF
import verify_access_autoconf
assert verify_access_autoconf.configurator != None
assert verify_access_autoconf.appliance != None
assert verify_access_autoconf.container != None
assert verify_access_autoconf.webseal != None
assert verify_access_autoconf.access_control != None
assert verify_access_autoconf.federation != None
EOF
