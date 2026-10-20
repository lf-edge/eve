# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# The EVE host rootfs: the first of the init: images of images/rootfs.yml.in
# and images/installer.yml.in, onto which the kernel, the firmware and the
# other init images (runc, containerd, memlogd, dom0-ztools, grub, gpt-tools,
# kexec, udev) are overlaid. It replaces linuxkit/init (PID 1, linuxkit's init
# programs and Alpine's busybox userland) and linuxkit/getty (the console
# login) with the same programs on the Ubuntu rootfs every other EVE
# container is built from.

FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build
# gcc: usermode-helper; the Go toolchain is part of the base
ENV BUILD_PKGS="gcc libc6-dev linux-libc-dev"
# busybox-static: PID 1 (busybox init running /etc/inittab), the hotplug
#   helper (mdev), the tools rc.init execs (modprobe, hwclock, ip) and
#   /bin/sh, all as on the Alpine host
# procps: ps with options, pgrep and pkill for the eve CLI (not in busybox)
# netcat-openbsd: nc -z, which the eve CLI uses and busybox's nc lacks
# musl: the loader of ctr and runc, the musl binaries of linuxkit's
#   containerd and runc images, which Alpine's init image used to provide
ENV PKGS="busybox-static procps netcat-openbsd musl"
RUN eve-ubuntu-deploy.sh

# linuxkit's init programs at the commit linuxkit/init:v1.3.0 was built from:
# /init (execs /sbin/init), rc.init (the sysinit of /etc/inittab: mounts the
# pseudo filesystems, then runs /etc/init.d), service (starts containerd and
# the onboot and services containers) and the kernel's usermode helper
ENV LINUXKIT_COMMIT=fc47fa1df34ce0c7dc4f340111e1fb25395922fd
ADD https://github.com/linuxkit/linuxkit.git#${LINUXKIT_COMMIT}:pkg/init /linuxkit/init

ENV GOPATH=/go PATH=$PATH:/go/bin
WORKDIR /linuxkit/init
RUN go-compile.sh /linuxkit/init/cmd/init && \
    go-compile.sh /linuxkit/init/cmd/rc.init && \
    go-compile.sh /linuxkit/init/cmd/service
RUN gcc -static -Wall -Werror -o /go/bin/usermode-helper usermode-helper.c

# Register linuxkit's init in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n linuxkit-init -v "$(printf '%.8s' "${LINUXKIT_COMMIT}")" -l Apache-2.0 -u https://github.com/linuxkit/linuxkit

# The host rootfs is /out itself, which the squashfs stores once for all the
# containers. Ubuntu's merged-/usr symlinks (/bin -> usr/bin, ...) become
# real directories: the kernel's /lib/modules, the firmware and the init
# overlays add real directories there, which cannot be merged onto a symlink.
# Each mirrors its /usr counterpart entry by entry, so both spellings of a
# path keep working: the dynamic loader where PT_INTERP names it
# (/lib64/ld-linux-x86-64.so.2, /lib/ld-linux-aarch64.so.1, also the
# overlays' loader aliases), dpkg's alternatives (/bin/nc.openbsd), and the
# Ubuntu tools under /bin and /sbin whatever PATH's order is.
RUN mkdir /stage && cp -a /out/. /stage/ && \
    for d in bin sbin lib lib64; do \
        [ -L "/stage/$d" ] || continue; \
        rm "/stage/$d" && mkdir "/stage/$d"; \
        for e in "/stage/usr/$d"/*; do ln -s "../usr/$d/${e##*/}" "/stage/$d/"; done; \
    done

# The busybox applets fill in where Ubuntu has no tool of that name (mount,
# login, modprobe, mdev, ip, less, vi, ...), at the paths busybox itself
# installs them. /bin/sh, and the sh of PATH, is busybox ash as on the Alpine
# host: the init scripts use ash features dash lacks. Note that Debian's
# busybox is a standalone shell: ash runs its own applet for any command
# name it has (ps, grep, nc, run-parts, ...) whatever PATH says, so the
# scripts it runs see busybox's tools, as they did on Alpine; a path with a
# slash (/usr/bin/nc) reaches the Ubuntu tool. See etc/profile.
# hadolint ignore=SC2046
RUN for a in $(/stage/usr/bin/busybox --list-full); do \
        case "$a" in \
            bin/*|sbin/*) t=../usr/bin/busybox ;; \
            usr/bin/*) t=busybox ;; \
            usr/sbin/*) t=../bin/busybox ;; \
            *) continue ;; \
        esac; \
        [ -e "/stage/$a" ] || [ -L "/stage/$a" ] || ln -s "$t" "/stage/$a"; \
    done && \
    ln -sf busybox /stage/usr/bin/sh

# rungetty.sh (dom0-ztools) starts agetty through setsid under this name
RUN ln -s setsid /stage/usr/bin/setsid.getty

# The init programs and linuxkit's /etc: inittab, the issue banner and the
# script that prints it on the console, the volumes init. rc.init runs every
# file in /etc/init.d, so the sysv scripts of Ubuntu packages (procps) go.
RUN rm -rf /stage/etc/init.d && \
    cp /go/bin/init /stage/init && \
    cp /go/bin/rc.init /stage/bin/rc.init && ln -s rc.init /stage/bin/rc.shutdown && \
    cp /go/bin/service /stage/usr/bin/service && \
    cp /go/bin/usermode-helper /stage/sbin/usermode-helper && \
    cp -a /linuxkit/init/etc/. /stage/etc/ && \
    ln -s /usr/bin/service /stage/etc/init.d/005-volumes

# What debootstrap took from the build host becomes the empty files the
# Alpine host had: rc.init names the host after its first NIC when
# /etc/hostname is empty, resolv.conf is written at runtime
RUN : > /stage/etc/hostname && : > /stage/etc/hosts && : > /stage/etc/resolv.conf
# etc/profile replaces Ubuntu's, see there
COPY etc/ /stage/etc/

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /
COPY --from=build /stage/ /
