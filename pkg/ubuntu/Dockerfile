# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# ubuntu snapshot dates can be found here: https://hub.docker.com/_/ubuntu/tags?name=resolute-
ARG UBUNTU_SNAPSHOT_DATE=20260927
FROM ubuntu:resolute-${UBUNTU_SNAPSHOT_DATE} AS builder

ARG TARGETARCH
ARG UBUNTU_SNAPSHOT_DATE
ARG UBUNTU_SNAPSHOT=${UBUNTU_SNAPSHOT_DATE}T000000Z

ENV MIRROR_PKGS="build-essential \
    gawk \
    autoconf \
    psmisc \
    iproute2 \
    passwd \
    vim \
    git \
    cmake \
    curl \
    wget \
    jq \
    lsof \
    gdb \
    openssh-client \
    openssh-server \
    make"

ENV DEBIAN_FRONTEND=noninteractive

# the base image ships no ca-certificates and the snapshot service is
# https-only; without the certs apt-get update ignores the mirror silently
# hadolint ignore=DL3008
RUN apt-get update && apt-get -y install --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
# all three pockets must be pinned: the base image already contains newer
# packages from -updates/-security than the frozen release pocket
RUN rm -Rf /etc/apt/sources.list.d && \
    for p in resolute resolute-updates resolute-security; do \
        echo "deb https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT} $p main restricted universe multiverse"; \
    done > /etc/apt/sources.list
# hadolint ignore=DL3009
RUN apt-get update
# hadolint ignore=DL3008
RUN apt-get -y install --no-install-recommends apt-file dpkg-dev strace
RUN apt-file update

RUN mkdir -p /mirror/archives

# hadolint ignore=DL3008
RUN apt-get -y install --no-install-recommends debootstrap
WORKDIR /root
# ca-certificates is included so apt inside /out can keep talking to the
# https-only snapshot until its sources are switched to the local mirror.
# the snapshot service intermittently answers 5xx and debootstrap, unlike
# apt, does not retry failed downloads, so rerun the whole bootstrap;
# --cache-dir carries already-fetched debs over to the next attempt
RUN i=0; until debootstrap --cache-dir=/mirror/archives --variant=minbase \
        --arch=${TARGETARCH} --include=ca-certificates resolute /out \
        "https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}"; do \
        i=$((i+1)); [ "$i" -ge 50 ] && exit 1; \
        rm -Rf /out; sleep 15; \
    done

# debootstrap can only bootstrap from the frozen release pocket; point /out
# at all three pinned pockets and dist-upgrade to the snapshot's current state
RUN for p in resolute resolute-updates resolute-security; do \
        echo "deb https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT} $p main"; \
    done > /out/etc/apt/sources.list
RUN chroot /out apt-get update
RUN chroot /out apt-get -y dist-upgrade

RUN chroot /out apt-get purge --allow-remove-essential -y procps
# findutils sed libbsd0 sensible-utils are still needed to install further packages
RUN chroot /out apt-get purge --allow-remove-essential -y gawk login login.defs bsdutils readline-common libsemanage2 mount bash gzip e2fsprogs ncurses-base ncurses-bin libext2fs2t64 sysvinit-utils logsave passwd
RUN rm -Rf /out/var/cache/apt/archives /out/usr/share/coreutils/locales
RUN rm -f /out/usr/share/locale/*/LC_MESSAGES/*.mo
RUN rm -Rf /out/usr/share/man /out/usr/share/doc
RUN rm -Rf /out/usr/share/bash-completion /out/usr/share/fish /out/usr/share/zsh

COPY recurse-debs.pl /root
# hadolint ignore=DL3008,DL3015,SC2086
RUN for i in ${MIRROR_PKGS}; do apt-get -yd install --reinstall -o dir::cache=/mirror $(/root/recurse-debs.pl $i); done
WORKDIR /mirror/archives
RUN dpkg-scanpackages -m . > Packages && gzip -n -f Packages
WORKDIR /

RUN echo "deb [trusted=yes] file:///mirror/archives/ ./" > /etc/apt/sources.list
RUN echo "deb [trusted=yes] file:///mirror/archives/ ./" > /out/etc/apt/sources.list
RUN rm -Rvf /etc/apt/sources.list.d
RUN rm -Rvf /out/etc/apt/sources.list.d
# hadolint ignore=DL3009
RUN apt-get update

FROM builder
RUN --mount=type=bind,from=builder,source=/mirror,target=/out/mirror chroot /out /usr/bin/apt-get update

COPY eve-ubuntu-deploy.sh register-sbom-pkg.sh /bin/
