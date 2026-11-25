# yom-vuln: yom-base + the vulnerable_server binaries, compiled once, plus
# the probe that measures their stack frame (contract 1: nobody hand-types
# the addresses; the service measures them at emulator build time).
#
# The probe cannot run here: docker build containers run with the default
# seccomp profile, which blocks personality(ADDR_NO_RANDOMIZE) -- the no-ASLR
# flag setarch sets. The emulation itself runs every node privileged
# (seedemu's compose template), where it is allowed, so the service measures
# with `docker run --security-opt seccomp=unconfined` instead.
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
# seedemu-base:2.0 ships /root/.bashrc = "exec zsh" (a nicety for humans).
# When the lab exploit's shellcode runs `bash -c <command>` with the socket as
# stdin, bash treats that like an rsh/ssh session, sources .bashrc, and zsh
# replaces it - the command is thrown away and the worm dies silently. The lab
# image must not do that (found via strace; see docs/architecture.md).
RUN printf '# yom-vuln: the stock "exec zsh" broke bash -c; removed for the lab\n' > /root/.bashrc
COPY --from=build /src/server /src/stack /src/stack-patched /opt/yom/vulnerable_server/bin/
COPY probe.py /opt/yom/vulnerable_server/probe.py
LABEL org.seedlabs.yom.image="yom-vuln"
