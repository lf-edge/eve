# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-recovertpm:9ba41a2b6386e9e8728fa336e26aa0009ffe0328 AS recovertpm
FROM lfedge/eve-bpftrace:545e3bbafb752d756923c8e2ec2d4869b0f7cd8c AS bpftrace
FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build
ENV BUILD_PKGS="curl tar make patch g++ gcc libc6-dev linux-libc-dev git zlib1g-dev pkg-config jq pciutils usbutils util-linux"
# Feel free to add additional packages here, but be aware that
# EVE's rootfs image can be no larger than 300Mb (and don't
# forget to check on all supported architectures: e.g. arm64
# binaries are typically larger than amd64 ones).
# apt is here so that collect-info.sh can add tools on a device with network access.
# musl: ctr, bind-mounted from the host, comes from linuxkit's Alpine built containerd image and is a musl binary
ENV PKGS="openssl openssh-client openssh-server tini util-linux mount ca-certificates pciutils usbutils tcpdump strace iproute2 curl zlib1g procps tar gzip dmidecode iptables dhcpcd-base tio socat hexedit netcat-openbsd bash less vim-tiny apt musl lsof net-tools kmod xxd busybox-static bridge-utils"

RUN eve-ubuntu-deploy.sh
# busybox provides every applet the Alpine shell had and a real package does not (arp,
# nslookup, traceroute, reboot, ...); existing tools win (bridge-utils: busybox brctl has
# no show/showstp). logread must stay a plain bind mount target: the host's logread is bound
# into /usr/bin and the applet's /usr/sbin link would come first in root's PATH.
RUN chroot /out /bin/busybox --install -s && rm -f /out/usr/bin/logread /out/usr/sbin/logread

ENV LSHW_VERSION="02.20"

# hadolint ignore=DL4006
ADD https://www.ezix.org/software/files/lshw-B.${LSHW_VERSION}.tar.gz lshw.tar.gz
RUN tar -xzvf lshw.tar.gz

WORKDIR /
COPY lshw/ lshw-B.${LSHW_VERSION}/

WORKDIR /lshw-B.${LSHW_VERSION}

# NLS stays enabled: with -DNONLS the no-op textdomain macros clash with glibc's
# libintl.h declarations; glibc provides gettext itself, no extra package needed
# hadolint ignore=SC2046
RUN for patch in *.patch; do \
    patch -p1 < "$patch"; \
    done && \
    make -j$(nproc) -C src VERSION=B.${LSHW_VERSION} NO_VERSION_CHECK=1 RPM_OPT_FLAGS=-O2 ZLIB=1 core && \
    make -j$(nproc) -C src VERSION=B.${LSHW_VERSION} NO_VERSION_CHECK=1 RPM_OPT_FLAGS=-O2 ZLIB=1 GZIP="gzip -n9" static && \
    cp src/lshw-static /out/usr/bin/lshw && strip /out/usr/bin/lshw

# Register lshw in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n lshw -v "B.${LSHW_VERSION}" -l GPL-2.0-only -u https://www.ezix.org/software/files/lshw

# tweaking various bit
WORKDIR /out
COPY debug-services.sh ssh-service.sh edgeview-collectinfo.sh spec.sh scripts/ ./usr/bin/

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]
# Ensure that the output of spec.sh is valid json
RUN ./usr/bin/spec.sh -v 2>/dev/null | jq . > /dev/null
RUN ./usr/bin/spec.sh 2>/dev/null | jq . > /dev/null
RUN mkdir /tmp/bin
COPY tests/lsusb /tmp/bin
RUN chmod a+x /tmp/bin/lsusb
RUN PATH=/tmp/bin:$PATH /out/usr/bin/spec.sh -u 2>/dev/null | jq .

RUN mkdir -p ./etc/ssh ./root/.ssh && chmod 0700 ./root/.ssh
# a login shell with line editing for the root account of the debug container
RUN sed -i -e 's#^root:\(.*\):/bin/sh$#root:\1:/bin/bash#' ./etc/passwd
# the host keys of a device are generated on first start (ssh-service.sh),
# never baked into the image
RUN rm -f ./etc/ssh/ssh_host_*
RUN rm -rf ./var/run && ln -s /run ./var/run
RUN sed -i -e 's#AllowTcpForwarding.*$#AllowTcpForwarding yes#' ./etc/ssh/sshd_config
# No account has a password, so key-only login changes nothing that is
# allowed; it stops sshd from offering password methods to the network.
RUN mkdir -p ./etc/ssh/sshd_config.d && \
    printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' \
      > ./etc/ssh/sshd_config.d/10-eve-pubkey-only.conf

RUN mkdir /bpftrace
COPY --from=bpftrace / /bpftrace
RUN mkdir -p /bpftrace/bpftrace-aotrt

# Fold bpftrace's package list into the SBOM DB. This has to be a deduplicating
# merge rather than a concatenation: both are built on the same Ubuntu rootfs
# and so share its base packages. Merging here rather than in the final stage
# keeps it in the one stage that has the helper -- the scratch stage only has
# what /out provides.
RUN merge-sbom-db.sh -o /out/var/lib/dpkg/status \
        /out/var/lib/dpkg/status /bpftrace/bpftrace-aotrt/var/lib/dpkg/status && \
    cp -a /bpftrace/bpftrace-aotrt/var/lib/dpkg/status.d/. /out/var/lib/dpkg/status.d/

# add recover-tpm to debug container
WORKDIR /
COPY --from=recovertpm /usr/bin/recovertpm /out/usr/bin/recovertpm

FROM build AS test
# run collect-info test
COPY collect-info-test /collect-info-test
WORKDIR /collect-info-test
RUN go test

FROM scratch
ENTRYPOINT []
WORKDIR /

COPY --from=build /out/ /
COPY --from=build /bpftrace/bpftrace-aotrt /

CMD ["/usr/bin/tini", "/usr/bin/debug-services.sh"]
