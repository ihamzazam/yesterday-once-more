#!/bin/bash
# Build the YOM images.
#
#   images/build.sh          yom-base:1  (python3, cryptography, eth-account, user seed)
#   images/build.sh vuln     yom-vuln:1  (yom-base + vulnerable_server binaries)
#   images/build.sh all
#
# Docker Hub is unreliable from some networks. If the stock SEED image is only
# present locally under seedemu's hashed dummy name, give it its real name
# first (adding a tag never deletes anything):
#   docker tag ad739b7b201eccafa592110d2bf214a7 handsonsecurity/seedemu-base:2.0
#
# A PyPI mirror can be passed through:  PIP_INDEX_URL=https://... images/build.sh
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
what="${1:-base}"

build_base() {
    docker build \
        --build-arg PIP_INDEX_URL="${PIP_INDEX_URL:-https://pypi.org/simple}" \
        -t yom-base:1 "$REPO/images/yom-base"
}

build_vuln() {
    docker build -f "$REPO/images/yom-vuln/Dockerfile" -t yom-vuln:1 \
        "$REPO/software/vulnerable_server"
}

case "$what" in
    base) build_base ;;
    vuln) build_vuln ;;
    all)  build_base; build_vuln ;;
    *) echo "usage: $0 [base|vuln|all]" >&2; exit 2 ;;
esac
