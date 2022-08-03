#!/bin/bash

export PIP_EXTRA_INDEX_URL="https://${ART_API_USER}:${ART_API_KEY}@na.artifactory.swg-devops.com/artifactory/api/pypi/sec-iam-isam-devops-team-pypi-local/simple"
pip install -r dev-requirements.txt
python setup.py sdist bdist_wheel
#twine upload --verbose --repository-url https://eu.artifactory.swg-devops.com/artifactory/api/pypi/sec-iam-components-pypi-local/ -u $ART_API_USER -p $ART_API_KEY dist/*
twine upload --verbose --repository-url https://na.artifactory.swg-devops.com/artifactory/api/pypi/sec-iam-isam-devops-team-pypi-local/ -u $ART_API_USER -p $ART_API_KEY dist/*
