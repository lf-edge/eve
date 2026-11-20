# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# KubeVirt's virt-launcher with its qemu-kvm rebuilt from the matching CentOS
# Stream 9 source RPM plus EVE's patches. Only the QEMU binary and its modules
# are replaced; QEMU modules must come from the same build as the binary.
# The launcher version must match versions.KubeVirt in pkg/kube/kube-init.
ARG LAUNCHER=quay.io/kubevirt/virt-launcher:v1.7.3@sha256:d46498935671508ccafe760fcbebab6644faeaf31f6d912cbad53b2859c37a46
ARG QEMU_NVR=qemu-kvm-9.1.0-20.el9

FROM quay.io/centos/centos:stream9@sha256:875f628a88425be59d5edf2aa81e9836dd803de564ce3f728f23c63660d65662 AS build
ARG QEMU_NVR
RUN dnf -y install dnf-plugins-core rpm-build cpio && dnf config-manager --set-enabled crb
ADD --checksum=sha256:255bff410e599b277c6e4ee5c2a91ec732086b5a0bcdd1a502263e479d25de4f \
    https://kojihub.stream.centos.org/kojifiles/packages/qemu-kvm/9.1.0/20.el9/src/${QEMU_NVR}.src.rpm /src/
COPY patches/ /src/patches/
# Newer Stream 9 compilers warn on code that built cleanly when the RPM was
# released, so do not turn warnings into errors.
RUN rpm -i --define '_topdir /rpm' /src/${QEMU_NVR}.src.rpm && \
    n=9000; for p in /src/patches/*.patch; do \
        cp "$p" /rpm/SOURCES/ && \
        last=$(grep -n '^Patch[0-9]*:' /rpm/SPECS/qemu-kvm.spec | tail -1 | cut -d: -f1) && \
        sed -i "${last}a Patch$n: $(basename "$p")" /rpm/SPECS/qemu-kvm.spec && \
        n=$((n + 1)); done && \
    sed -i 's/^%global enable_werror 1/%global enable_werror 0/' /rpm/SPECS/qemu-kvm.spec && \
    dnf -y builddep /rpm/SPECS/qemu-kvm.spec
RUN rpmbuild -bb --nocheck --define '_topdir /rpm' /rpm/SPECS/qemu-kvm.spec > /rpm/build.log 2>&1 || \
    { tail -100 /rpm/build.log; exit 1; }
RUN grep -q vfio_pci_rom_lists_device /rpm/BUILD/qemu-*/hw/vfio/pci.c && \
    mkdir /out && cd /out && \
    for r in /rpm/RPMS/*/qemu-kvm-core-9*.rpm /rpm/RPMS/*/qemu-kvm-device-*.rpm; do \
        rpm2cpio "$r" | cpio -idm --quiet; done

FROM ${LAUNCHER}
COPY --from=build /out/usr/libexec/qemu-kvm /usr/libexec/qemu-kvm
COPY --from=build /out/usr/lib64/qemu-kvm/ /usr/lib64/qemu-kvm/
