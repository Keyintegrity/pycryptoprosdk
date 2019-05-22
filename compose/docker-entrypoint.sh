#!/usr/bin/env bash

set -e

python ./setup.py build_ext --inplace
python -m unittest discover
