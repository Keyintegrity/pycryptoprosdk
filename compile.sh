#!/usr/bin/env bash

set -e

rm -rf ./build
rm -f ./pycryptoprosdk/*.so

python setup.py build_ext --inplace
