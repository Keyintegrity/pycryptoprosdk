#!/usr/bin/env bash

rm -rf ./build \
  && rm -f ./pycryptoprosdk/libpycades.cpython-* \
  && python ./setup.py build_ext --inplace
