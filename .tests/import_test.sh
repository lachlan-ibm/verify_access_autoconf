#!/bin/sh

#!/bin/bash

export HOME=$( realpath . )
python setup.py sdist bdist_wheel

pip install dist/*.whl

cd "`basename $0`"

python import_test.py
