#!/bin/sh

#!/bin/bash
export PIP_EXTRA_INDEX_URL="https://${ART_API_USER}:${ART_API_KEY}@na.artifactory.swg-devops.com/artifactory/api/pypi/sec-iam-isam-devops-team-pypi-local/simple"

export HOME=$( realpath . )
python setup.py sdist bdist_wheel

pip install `ls $HOME/dist/*.whl`
cd "`dirname $0`"

python <<EOF
import verify-access-configurator
assert verify-access-configurator.configurator != None
assert verify-access-configurator.appliance != None
assert verify-access-configurator.container != None
assert verify-access-configurator.webseal != None
assert verify-access-configurator.access_control != None
assert verify-access-configurator.federation != None
EOF
