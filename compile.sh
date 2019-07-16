#!/usr/bin/env bash

rm -rf ./build
rm -f ./pycryptoprosdk/*.so

python setup.py build
cp ./build/*/pycryptoprosdk/*.so ./pycryptoprosdk
