# yom-vuln: yom-base + the vulnerable_server binaries, compiled once.
#
# Build (from the repo root):   images/build.sh vuln
FROM yom-base:1 AS build
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc gcc-multilib libc6-dev-i386 make \
 && rm -rf /var/lib/apt/lists/*
COPY src/ /src/
RUN make -C /src all

FROM yom-base:1
COPY --from=build /src/server /src/stack /src/stack-patched /opt/yom/vulnerable_server/bin/
LABEL org.seedlabs.yom.image="yom-vuln"
