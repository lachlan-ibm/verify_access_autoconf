#!/bin/sh

#!/bin/bash

export HOME=$( realpath . )
python setup.py sdist bdist_wheel

pip install `ls $HOME/dist/*.whl` --extra-index https://${ART_API_USER}:${ART_API_KEY}@na.artifactory.swg-devops.com/artifactory/api/pypi/sec-iam-isam-devops-team-pypi-local/
cd "`dirname $0`"

python import_test.py
