#!/bin/sh

#!/bin/bash

cat <<EOF > ${HOME}/pip.conf
extra-index-url = https://${ART_API_USER}:${ART_API_KEY}@na.artifactory.swg-devops.com/artifactory/api/pypi/sec-iam-isam-devops-team-pypi-local/simple
EOF

export HOME=$( realpath . )
python setup.py sdist bdist_wheel

pip install `ls $HOME/dist/*.whl`
cd "`dirname $0`"

python <<EOF
try:
    import verify_access_configurator
    assert verify_access_configurator.configurator != None
    assert verify_access_configurator.appliance != None
    assert verify_access_configurator.container != None
    assert verify_access_configurator.webseal != None
    assert verify_access_configurator.access_control != None
    assert verify_access_configurator.federation != None
except:
    assert False, "Import test failed"
EOF
