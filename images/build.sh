#!/bin/bash
# Build the YOM base image (tag: yom-base:1).
#
# Docker Hub is unreliable from some networks. If the stock SEED image is only
# present locally under seedemu's hashed dummy name, give it its real name
# first (adding a tag never deletes anything):
#   docker tag ad739b7b201eccafa592110d2bf214a7 handsonsecurity/seedemu-base:2.0
#
# A PyPI mirror can be passed through:  PIP_INDEX_URL=https://... images/build.sh
set -euo pipefail
cd "$(dirname "$0")/yom-base"
docker build \
    --build-arg PIP_INDEX_URL="${PIP_INDEX_URL:-https://pypi.org/simple}" \
    -t yom-base:1 .
