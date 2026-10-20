# Copyright (c) 2018-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Dockerfile to build pillar

# use the same set of packages for simplicity
ARG BUILD_PKGS_BASE="git gcc linux-libc-dev libc6-dev make libpam0g-dev m4 findutils util-linux patch tar \
                     uuid-dev libtirpc-dev libblkid-dev libssl-dev zlib1g-dev pkg-config"

# we use the same image in several places
ARG EVE_UBUNTU_IMAGE=lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544

FROM lfedge/eve-uefi:cbe04da0bf4436fdffbebed11a6a436d31519189 AS uefi-build
# qemu-img and qemu-nbd of the qemu that runs the VMs; Ubuntu's qemu-utils would
# drag python3 in through ubuntu-virt
FROM lfedge/eve-xen-tools:04383aadea99b1bedb416fe8165dc3a128be815b AS qemu
# the zfs userland pillar links against and ships, see pkg/dom0-ztools
FROM lfedge/eve-dom0-ztools:926579af8ae3f33aec8f4257bfbd7da4ae5a8881  AS zfs

# native build
# hadolint ignore=DL3006
FROM ${EVE_UBUNTU_IMAGE} AS build-native
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-ubuntu-deploy.sh
ENV CROSS_COMPILE_ENV=""
COPY --from=zfs / /zfs/
RUN while read -r x; do mkdir -p "$(dirname "$x")"; cp -P "/zfs$x" "$x"; done < /zfs/etc/zfs-files

# cross build: Ubuntu's cross compiler on the build host, with a sysroot made
# from the target's eve-ubuntu rootfs (libraries, headers, the zfs userland)
# hadolint ignore=DL3006,DL3029
FROM --platform=${BUILDPLATFORM} ${EVE_UBUNTU_IMAGE} AS build-cross
ARG BUILD_PKGS_BASE
RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-ubuntu-deploy.sh

# hadolint ignore=DL3006
FROM ${EVE_UBUNTU_IMAGE} AS cross-compile-libs
ENV PKGS="libc6-dev linux-libc-dev libgcc-s1 uuid-dev libtirpc-dev libblkid-dev libssl-dev zlib1g-dev libpam0g-dev"
RUN eve-ubuntu-deploy.sh
COPY --from=zfs / /zfs/
RUN while read -r x; do mkdir -p "/out$(dirname "$x")"; cp -P "/zfs$x" "/out$x"; done < /zfs/etc/zfs-files

FROM build-cross AS build-cross-target-arm64
RUN BUILD_PKGS=gcc-aarch64-linux-gnu eve-ubuntu-deploy.sh
ENV CROSS_COMPILE_ENV=aarch64-linux-gnu-
FROM build-cross AS build-cross-target-amd64
RUN BUILD_PKGS=gcc-x86-64-linux-gnu eve-ubuntu-deploy.sh
ENV CROSS_COMPILE_ENV=x86_64-linux-gnu-

# hadolint ignore=DL3006
FROM build-cross-target-${TARGETARCH} AS build-cross-target
COPY --from=cross-compile-libs /out/ /sysroot/
ENV CGO_CFLAGS="--sysroot=/sysroot"
ENV CGO_LDFLAGS="--sysroot=/sysroot"

# cross-compilers
FROM build-cross-target AS target-arm64-build-amd64
FROM build-cross-target AS target-amd64-build-arm64
# native
FROM build-native AS target-amd64-build-amd64
FROM build-native AS target-arm64-build-arm64

# hadolint ignore=DL3006
FROM target-${TARGETARCH}-build-${BUILDARCH} AS build
ARG DEV=n
ARG TEST_TOOLS=n
ARG TARGETARCH

# some parts of pillar are build conditionally based on the hypervisor
ARG HV

ENV CC=${CROSS_COMPILE_ENV}gcc

# building with runtime stats
ARG RSTATS=n
ARG RSTATS_ENDPOINT=
ARG RSTATS_TAG=
ARG IMM_PROFILING=n
ENV IMM_PROFILING=${IMM_PROFILING}
ARG ARTIFICIAL_LEAK=n
ENV ARTIFICIAL_LEAK=${ARTIFICIAL_LEAK}
ARG FAULT_INJECTION=n
ENV FAULT_INJECTION=${FAULT_INJECTION}
ARG COVER=n

COPY ./  /pillar/

# go vet/format and go install
WORKDIR /pillar

ENV GOFLAGS=-mod=vendor
ENV GO111MODULE=on
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=${TARGETARCH}
ARG GOPKGVERSION

# make LK build args affect a layer, so value change will invalidate cache
RUN echo "IMM_PROFILING: ${IMM_PROFILING}"
RUN echo "ARTIFICIAL_LEAK: ${ARTIFICIAL_LEAK}"
RUN echo "FAULT_INJECTION: ${FAULT_INJECTION}"
RUN echo "COVER: ${COVER}"

# hadolint ignore=DL4006
RUN --mount=type=cache,target=/root/.cache/go-build echo "Running go vet" && make HV="$HV" vet && \
    echo "Running go fmt" && ERR="$(find . -name \*.go | grep -v /vendor/ | xargs gofmt -d -e -l -s)" && \
       if [ -n "$ERR" ] ; then printf 'go fmt Failed - ERR: %s' "$ERR" ; exit 1 ; fi && \
       make ZARCH=${TARGETARCH} HV="$HV" DEV="$DEV" COVER="$COVER" RSTATS=$RSTATS RSTATS_ENDPOINT=$RSTATS_ENDPOINT RSTATS_TAG=$RSTATS_TAG IMM_PROFILING=$IMM_PROFILING ARTIFICIAL_LEAK=$ARTIFICIAL_LEAK FAULT_INJECTION=$FAULT_INJECTION DISTDIR=/final/opt/zededa/bin BUILD_VERSION=${GOPKGVERSION} build

# Generate the list of non-persistent pubsub topics from the sources being
# built; upgradeconverter removes the matching directories under
# /persist/status at boot (see docs/IPC.md). Generating it here keeps the
# list in sync with the code by construction. The build fails on an empty
# list as a sanity check: pillar always has non-persistent publications, so
# an empty list means the generator is broken (the resulting failure mode is
# benign - upgradeconverter would simply clean up nothing).
RUN --mount=type=cache,target=/root/.cache/go-build mkdir -p /final/opt/zededa/etc && \
    GOOS='' GOARCH='' go run ./tools/pubsubcheck -list-non-persistent . \
      > /final/opt/zededa/etc/non-persistent-pubsub-topics && \
    test -s /final/opt/zededa/etc/non-persistent-pubsub-topics

WORKDIR /

ENV DELVE_VERSION 1.20.1
ENV DELVE_SOURCE=https://github.com/go-delve/delve/archive/refs/tags/v${DELVE_VERSION}.tar.gz
# hadolint ignore=DL3020
ADD ${DELVE_SOURCE} /delve.tar.gz
RUN if [ ${DEV} = "y" ]; then tar --absolute-names -xz < /delve.tar.gz; fi
WORKDIR /delve-${DELVE_VERSION}
RUN --mount=type=cache,target=/root/.cache/go-build if [ ${DEV} = "y" ]; then \
    GOFLAGS='' CGO_ENABLED=0 go build -ldflags "-s -w -extldflags '-static'" github.com/go-delve/delve/cmd/dlv && \
    cp dlv /final/opt/ ; \
fi
WORKDIR /
# hadolint ignore=DL3008
RUN --mount=type=cache,target=/root/.cache/go-build if [ "${TEST_TOOLS}" = "y" ]; then \
    apt-get -y install --no-install-recommends dmidecode pciutils; \
    GOBIN=/final/opt/ GOFLAGS="" go install gotest.tools/gotestsum@v1.7.0; \
fi

FROM lfedge/eve-fscrypt:1666aba771b27456204a7382149dfacbb97d48ee AS fscrypt
FROM lfedge/eve-gpt-tools:a18f4b89a5b6ffd6a282f99b5aa1eda57946d8ef AS gpttools
FROM lfedge/eve-storage-resizer:ad51054ea6af2262b6442ef482e509e1b1f884a2 AS storage-resizer

# collector collects everything together and then does any processing like stripping binaries.
# We use this interim "collector" so that we can do processing.
# hadolint ignore=DL3006
FROM ${EVE_UBUNTU_IMAGE} AS collector
ENV BUILD_PKGS="patch"
ENV PKGS="pciutils xz-utils bash iptables iproute2 coreutils dmidecode libbz2-1.0 libuuid1 ipset curl radvd ethtool \
    util-linux mount e2fsprogs libssl3t64 xorriso jq keyutils ca-certificates hdparm libtirpc3t64 libblkid1 zlib1g \
    rsync chrony wpasupplicant dnsmasq-base dhcpcd-base net-tools procps kmod uuid-runtime openssl gzip tar bsdutils rfkill busybox-static"
RUN eve-ubuntu-deploy.sh
# zedrouter runs dnsmasq as nobody:nobody; Debian names gid 65534 nogroup
RUN echo "nobody:x:65534:" >> /out/etc/group
# domainmgr builds cloud-init ISOs with mkisofs; Ubuntu ships only xorriso's emulation
RUN ln -s xorrisofs /out/usr/bin/mkisofs && test -x /out/usr/bin/mkisofs
# zboot reset/poweroff run busybox reboot -n -f and poweroff -f, as any Alpine based container could
RUN for a in reboot poweroff halt; do ln -s ../bin/busybox /out/usr/sbin/$a; done

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

WORKDIR /

RUN mkdir -p /out/usr/share/ovmf
COPY --from=uefi-build /OVMF_VARS.fd /out/usr/share/ovmf/OVMF_VARS.fd

# the zfs userland of pkg/dom0-ztools, by its file list
COPY --from=zfs / /zfs/
RUN while read -r x; do mkdir -p "/out$(dirname "$x")"; cp -P "/zfs$x" "/out$x"; done < /zfs/etc/zfs-files
# qemu-img and qemu-nbd with their libraries and dpkg records, see above
COPY --from=qemu / /qemu/
RUN copy-with-libs.sh -m -r /qemu -o /out /usr/lib/xen/bin/qemu-img /usr/lib/xen/bin/qemu-nbd && \
    ln -s ../lib/xen/bin/qemu-img /out/usr/bin/qemu-img && ln -s ../lib/xen/bin/qemu-nbd /out/usr/bin/qemu-nbd
COPY --from=fscrypt /opt/zededa/bin /out/opt/zededa/bin
COPY --from=gpttools / /out
# baseosmgr execs /usr/bin/storage-resizer for the online check/backup/grow steps
# of the EVE-kvm<->EVE-k boot-disk conversion (pkg/pillar/diskconvert).
COPY --from=storage-resizer /usr/bin/storage-resizer /out/usr/bin/storage-resizer
# we use final directory and move the line to the bottom
# to avoid conflicts and speedup re-builds
COPY --from=build /final /out

COPY scripts/device-steps.sh \
    scripts/onboot.sh \
    scripts/veth.sh \
    scripts/dhcpcd.sh \
    scripts/direct-net.sh \
    scripts/copy-image-to-qcow.sh \
    /out/opt/zededa/bin/
COPY conf/lisp.config.base /out/var/tmp/zededa/lisp.config.base

COPY patches/* /sys-patches/
# hadolint ignore=SC1097
RUN set -e && for patch in /sys-patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p0 --no-backup-if-mismatch -r /tmp/deleteme.rej < "$patch"; \
    done

# And now a few local tweaks
COPY rootfs/ /out

# We will start experimenting with stripping go binaries on ARM only for now
# hadolint ignore=DL3008
RUN if [ "$(uname -m)" = "aarch64" ] ; then                                             \
       apt-get -y install --no-install-recommends binutils file                          ;\
       find /out -type f -executable -exec file {} \; | grep 'not stripped' | cut -f1 -d: |\
       xargs strip                                                                     ;\
    fi

# Merge the dpkg status records from every source pkg into /out so the final
# SBOM reflects entries from every contributing pkg image: the source-built
# packages come as one file each below status.d, the Ubuntu packages behind the
# zfs userland as the records of the dom0-ztools image.
COPY --from=zfs /var/lib/dpkg/status.d /out/var/lib/dpkg/status.d
COPY --from=fscrypt /var/lib/dpkg/status.d /out/var/lib/dpkg/status.d
COPY --from=uefi-build /var/lib/dpkg/status.d /out/var/lib/dpkg/status.d
RUN merge-sbom-db.sh -o /out/var/lib/dpkg/status /out/var/lib/dpkg/status /zfs/var/lib/dpkg/status

FROM scratch

SHELL ["/bin/sh", "-c"]

COPY --from=collector /out /

# FIXME: replace with tini+monit ASAP
WORKDIR /
CMD ["/init.sh"]
