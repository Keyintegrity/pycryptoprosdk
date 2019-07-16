#!/usr/bin/env bash

rm -rf ./build
rm -f ./pycryptoprosdk/*.so

python setup.py build_ext --inplace
