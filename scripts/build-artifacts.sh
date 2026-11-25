#!/usr/bin/env bash
# Rebuilds the two Lambda artifacts in artifacts/ from source.
#   origin-secret-rotate.zip         lambda/lambda_function.py
#   python-requests-lambda-layer.zip packages pinned in lambda/requirements.txt,
#                                    built for the Lambda python3.14 runtime on x86_64
set -euo pipefail
cd "$(dirname "$0")/.."
PY_VERSION=3.14
rm -rf build && mkdir -p build/layer/python

python3 -m pip install --quiet --no-compile \
  --platform manylinux2014_x86_64 --implementation cp --python-version "$PY_VERSION" \
  --only-binary=:all: --target build/layer/python -r lambda/requirements.txt

rm -f artifacts/python-requests-lambda-layer.zip artifacts/origin-secret-rotate.zip
(cd build/layer && zip -qrX ../../artifacts/python-requests-lambda-layer.zip python)
(cd lambda && zip -qX ../artifacts/origin-secret-rotate.zip lambda_function.py)

unzip -p artifacts/origin-secret-rotate.zip lambda_function.py | cmp -s - lambda/lambda_function.py \
  || { echo "origin-secret-rotate.zip does not match lambda/lambda_function.py" >&2; exit 1; }
rm -rf build
ls -l artifacts/
