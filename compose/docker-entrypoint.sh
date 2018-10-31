#!/usr/bin/env bash

python ./setup.py build_ext --inplace
python -m unittest discover
