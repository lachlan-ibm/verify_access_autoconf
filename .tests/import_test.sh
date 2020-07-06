#!/bin/sh

#!/bin/bash

export HOME=$( realpath . )
python setup.py sdist bdist_wheel

pip install *.whl

python import_test.py
