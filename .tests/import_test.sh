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
    import ivsa_configurator
    assert isva_configurator.configurator != None
    assert isva_configurator.appliance != None
    assert isva_configurator.docker != None
    assert isva_configurator.appliance != None
    assert isva_configurator.web != None
    assert isva_configurator.aac != None
    assert isva_configurator.fed != None
except:
    assert False, "Import test failed"
EOF
