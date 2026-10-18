# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# lfedge/eve-ubuntu is the base image of every other EVE package: a builder
# with the toolchains and a local apt mirror under /mirror, plus a minimal
# Ubuntu rootfs under /out that consumers populate with eve-ubuntu-deploy.sh
# and copy into their FROM scratch stage. Everything is resolved against one
# snapshot.ubuntu.com timestamp, so a rebuild yields the same package set.
#
# the dates of the ubuntu images can be found here: https://hub.docker.com/_/ubuntu/tags?name=resolute-
ARG UBUNTU_IMAGE_DATE=20260927
# the archive state everything is resolved against (https://snapshot.ubuntu.com).
# The base image already carries the updates published up to the moment it was
# built, and apt will not downgrade them, so the snapshot must not be older
# than the image's packages (compare dpkg -l of the image with the snapshot's
# Packages indexes when moving either of the two).
ARG UBUNTU_SNAPSHOT=20260927T000000Z
FROM ubuntu:resolute-${UBUNTU_IMAGE_DATE} AS builder
SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

ARG TARGETARCH
ARG UBUNTU_SNAPSHOT
ARG UBUNTU_RELEASE=resolute

ENV DEBIAN_FRONTEND=noninteractive

COPY apt.conf /etc/apt/apt.conf.d/01-eve

# all three pockets must be pinned: the base image already contains newer
# packages from -updates/-security than the frozen release pocket; the perl
# that dpkg-dev needs, for one, refuses to install on top of a newer perl-base
RUN rm -Rf /etc/apt/sources.list.d && \
    for p in ${UBUNTU_RELEASE} ${UBUNTU_RELEASE}-updates ${UBUNTU_RELEASE}-security; do \
        echo "deb https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT} $p main restricted universe multiverse"; \
    done > /etc/apt/sources.list
# the base image ships no ca-certificates and the snapshot service is
# https-only: fetch the certificates from the snapshot without verifying the
# TLS peer, the archive signature still vouches for what is downloaded. Taking
# them from the moving archive instead would drag newer openssl and libssl
# than the snapshot has into the image, which later breaks the resolution of
# every package depending on an exact libssl version.
# hadolint ignore=DL3008,DL3009
RUN apt-get -o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false update && \
    apt-get -o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false -y install --no-install-recommends ca-certificates
# hadolint ignore=DL3009
RUN apt-get update
# systemd-standalone-sysusers satisfies the "systemd | systemd-standalone-sysusers"
# dependency of udev, chrony, dhcpcd, openssh-server and friends, so that
# installing any of them, here or into /out, never drags systemd in.
# golang-go is the Go toolchain of every Go build in pkg/.
# hadolint ignore=DL3008
RUN apt-get -y install --no-install-recommends apt-file dpkg-dev strace systemd-standalone-sysusers golang-go pax-utils
RUN apt-file update
ENV GOTOOLCHAIN=local

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
        --arch=${TARGETARCH} --include=ca-certificates ${UBUNTU_RELEASE} /out \
        "https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}"; do \
        i=$((i+1)); [ "$i" -ge 50 ] && exit 1; \
        rm -Rf /out; sleep 15; \
    done

# debootstrap can only bootstrap from the frozen release pocket; point /out
# at all three pinned pockets and dist-upgrade to the snapshot's current state
RUN for p in ${UBUNTU_RELEASE} ${UBUNTU_RELEASE}-updates ${UBUNTU_RELEASE}-security; do \
        echo "deb https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT} $p main universe"; \
    done > /out/etc/apt/sources.list.upstream && \
    cp /out/etc/apt/sources.list.upstream /out/etc/apt/sources.list
COPY apt.conf /out/etc/apt/apt.conf.d/01-eve
RUN chroot /out apt-get update
RUN chroot /out apt-get -y dist-upgrade

# resolute's default coreutils are the uutils ones, EVE's scripts are written
# for GNU coreutils; see above for systemd-standalone-sysusers
RUN chroot /out apt-get -y --allow-remove-essential install coreutils-from-gnu coreutils-from-uutils- rust-coreutils- systemd-standalone-sysusers
RUN chroot /out apt-get purge --allow-remove-essential -y procps
# libc6 depends on the extra charset conversion modules (8 MB of CJK and
# legacy encodings); EVE only ever converts to and from UTF-8, which libc
# does on its own, so the modules go and the package record stays
# mtools (mkconf, mkimage-*, installer) converts file names through DOS code
# page 850 with iconv, so that module and the US one stay
# hadolint ignore=SC2046
RUN rm -f $(chroot /out dpkg -L libc-gconv-modules-extra | grep '\.so$' | grep -v '/IBM\(850\|437\)\.so$' | sed 's|^|/out|')
# findutils sed libbsd0 sensible-utils are still needed to install further packages
RUN chroot /out apt-get purge --allow-remove-essential -y gawk login login.defs bsdutils readline-common libsemanage2 mount bash gzip e2fsprogs ncurses-base ncurses-bin libext2fs2t64 sysvinit-utils logsave passwd
RUN rm -Rf /out/var/cache/apt/archives /out/usr/share/coreutils/locales
RUN rm -f /out/usr/share/locale/*/LC_MESSAGES/*.mo
RUN rm -Rf /out/usr/share/man /out/usr/share/doc
RUN rm -Rf /out/usr/share/bash-completion /out/usr/share/fish /out/usr/share/zsh

# packages installed into /out later must stay as lean: no documentation and
# locales (dpkg path-exclude), and no services started by maintainer scripts
COPY dpkg-nodoc.cfg /out/etc/dpkg/dpkg.cfg.d/01-eve-nodoc
RUN printf '#!/bin/sh\nexit 101\n' > /out/usr/sbin/policy-rc.d && chmod 755 /out/usr/sbin/policy-rc.d

# /mirror/archives: the transitive Depends/Pre-Depends closure (recurse-debs.pl)
# of mirrors/<release>/main plus main.<arch>. One apt-get transaction per
# listed package: packages that conflict with each other (busybox and
# busybox-static, ...) can then share the mirror, and apt's own dependency
# resolution still completes the closure should recurse-debs.pl miss a package.
COPY recurse-debs.pl /root/
COPY mirrors/${UBUNTU_RELEASE} /tmp/mirrors/
# hadolint ignore=DL3008,DL3015,SC2046,SC2086
RUN for i in $(sed -e 's/#.*//' /tmp/mirrors/main "/tmp/mirrors/main.$(dpkg --print-architecture)" 2>/dev/null); do \
        apt-get -yd install --reinstall -o dir::cache=/mirror $(/root/recurse-debs.pl $i) || exit 1; \
    done
WORKDIR /mirror/archives
RUN dpkg-scanpackages -m . > Packages && gzip -n -f Packages
WORKDIR /

# the builder installs straight from the mirror. eve-ubuntu-deploy.sh runs apt
# for /out outside of the chroot, with the copy: method, so that the debs land
# in /out/var/cache/apt/archives where dpkg, chrooted into /out, can read them.
# sources.list.upstream is put back when the deploy script is done, so that a
# container with network access can still apt-get install from the snapshot.
RUN echo "deb [trusted=yes] file:///mirror/archives/ ./" > /etc/apt/sources.list && rm -rf /etc/apt/sources.list.d
RUN echo "deb [trusted=yes] copy:///mirror/archives/ ./" > /out/etc/apt/sources.list.mirror && \
    rm -rf /out/etc/apt/sources.list.d /out/var/lib/apt/lists/*
# hadolint ignore=DL3009
RUN apt-get update

# apt is not needed inside /out, eve-ubuntu-deploy.sh runs it from the builder;
# gpgv and the keyring only served apt's signature checks
RUN mkdir -p /out/etc/apt/preferences.d && \
    cp /out/etc/apt/sources.list.mirror /out/etc/apt/sources.list && \
    apt-get -o Dir=/out -o DPkg::Chroot-Directory=/out update && \
    apt-get -o Dir=/out -o DPkg::Chroot-Directory=/out -y --allow-remove-essential purge apt libapt-pkg7.0 gpgv ubuntu-keyring && \
    apt-get -o Dir=/out -o DPkg::Chroot-Directory=/out -y --allow-remove-essential autoremove --purge && \
    cp /out/etc/apt/sources.list.upstream /out/etc/apt/sources.list && \
    rm -rf /out/var/cache/apt/archives/*.deb /out/var/cache/apt/*.bin /out/var/lib/apt/lists/* \
        /out/var/cache/debconf/* /out/var/log/apt /out/var/log/dpkg.log /out/var/log/alternatives.log /out/var/log/bootstrap.log
COPY apt.conf /out/etc/apt/apt.conf.d/01-eve

COPY eve-ubuntu-deploy.sh register-sbom-pkg.sh merge-sbom-db.sh go-compile.sh copy-with-libs.sh eve-mkinitramfs.sh /bin/
