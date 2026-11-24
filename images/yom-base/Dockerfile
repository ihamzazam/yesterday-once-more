# YOM base image: everything a toolkit runtime needs, baked in once so that
# emulator builds never pip-install inside every container.
#
# Build (from the repo root):   images/build.sh
#
# FROM is the stock SEED Emulator host image (seedemu 2.0.0 default for hosts).
FROM handsonsecurity/seedemu-base:2.0
ARG DEBIAN_FRONTEND=noninteractive
ARG PIP_INDEX_URL=https://pypi.org/simple

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-cryptography \
 && rm -rf /var/lib/apt/lists/*

# eth-account 0.13.x brings eth-abi/eth-utils (used by the payment client).
RUN pip3 install --break-system-packages --no-cache-dir \
        --index-url "$PIP_INDEX_URL" --default-timeout 120 \
        "eth-account==0.13.7"

# Lab user whose home holds victim documents.
RUN id seed >/dev/null 2>&1 || useradd -m -s /bin/bash seed

LABEL org.seedlabs.yom.image="yom-base"
