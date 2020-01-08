FROM lfedge/eve-alpine:8727b17d0d3c6d85ed6634637e76e6fbab83b726 as kernel-build

RUN apk add --no-cache \
    gcc=8.3.0-r0 \
    make=4.2.1-r2 \
    libc-dev=0.7.1-r0 \
    dev86=0.16.21-r0 \
    xz-dev=5.2.4-r0 \
    perl=5.26.3-r0 \
    bash=4.4.19-r1 \
    python2-dev=2.7.16-r2 \
    gettext=0.19.8.1-r4 \
    iasl=20181213-r0 \
    util-linux-dev=2.33-r0 \
    ncurses-dev=6.1_p20190105-r0 \
    glib-dev=2.58.1-r3 \
    pixman-dev=0.34.0-r6 \
    libaio-dev=0.3.111-r0 \
    yajl-dev=2.1.0-r0 \
    argp-standalone=1.3-r3 \
    linux-headers=4.18.13-r1 \
    git=2.20.2-r0 \
    patch=2.7.6-r6 \
    texinfo=6.5-r1 \
    curl=7.64.0-r3 \
    tar=1.32-r0 \
    bash=4.4.19-r1 \
    socat=1.7.3.2-r5 \
    openssh=7.9_p1-r6 \
    python3=3.6.9-r2 \
    libc-dev=0.7.1-r0 \
    openssl-dev=1.1.1d-r2 \
    openssl=1.1.1d-r2 \
    libpciaccess=0.14-r0 \
    libpciaccess-dev=0.14-r0 \
    bsd-compat-headers=0.7.1-r0 \
    libusb=1.0.22-r0 \
    libusb-dev=1.0.22-r0 \
    gnu-efi-dev=3.0.4-r1

RUN if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi
RUN pip3 install kconfiglib==12.14.1

ENV ACRN_VERSION 1.3
ENV ACRN_SOURCE=https://github.com/projectacrn/acrn-hypervisor/archive/v${ACRN_VERSION}.tar.gz
RUN \
    [ -f "$(basename ${ACRN_SOURCE})" ] || curl -fsSLO "${ACRN_SOURCE}" && \
    tar --absolute-names -xz < "$(basename ${ACRN_SOURCE})" && mv "/acrn-hypervisor-${ACRN_VERSION}" /acrn-hypervisor
RUN ls -l /acrn-hypervisor
# Apply local patches
COPY patches-${ACRN_VERSION} /patches
WORKDIR /acrn-hypervisor
RUN set -e && for patch in /patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p1 < "$patch"; \
    done

COPY grub-hv.cfg /out/EFI/BOOT/grub-hv.cfg
RUN mkdir -p /out/boot /out/usr/bin /out/usr/lib/systemd/system           \
             /out/usr/share/acrn/bios /out/usr/share/acrn/samples/generic \
             /out/usr/share/acrn/samples/nuc /out/usr/lib/acrn
RUN if [ `uname -m` = "x86_64" ] ; then \
   make SCENARIO=industry PLATFORM=uefi BOARD=generic &&\
   cp /acrn-hypervisor/build/misc/tools/acrntrace /out/usr/bin/ &&\
   cp /acrn-hypervisor/build/misc/tools/acrntrace /out/usr/bin/ &&\
   cp /acrn-hypervisor/build/misc/tools/acrnlog.service /out/usr/lib/systemd/system/acrnlog.service &&\
   cp /acrn-hypervisor/build/misc//tools/acrnlog /out/usr/bin/ &&\
   cp /acrn-hypervisor/build/misc/tools/acrnctl /out/usr/bin/ &&\
   cp /acrn-hypervisor/build/misc/tools/acrnd /out/usr/bin/ &&\
   cp /acrn-hypervisor/build/misc/tools/libacrn-mngr.a /out/usr/bin/ &&\
   cp /acrn-hypervisor/build/misc/tools/acrnd.service /out/usr/lib/systemd/system/acrnd.service &&\
   cp /acrn-hypervisor/build/hypervisor/acrn.bin /out/usr/lib/acrn &&\
   cp /acrn-hypervisor/build/hypervisor/acrn.efi /out/usr/lib/acrn &&\
   cp /acrn-hypervisor/build/hypervisor/acrn.32.out /out/usr/lib/acrn &&\
   cp /acrn-hypervisor/build/hypervisor/acrn.32.out /out/boot &&\
   cp /acrn-hypervisor/build/devicemodel/acrn-dm /out/usr/bin/ &&\
   cp /acrn-hypervisor/devicemodel/bios/* /out/usr/share/acrn/bios/ &&\
   cp /acrn-hypervisor/misc/efi-stub/clearlinux/acrn.conf /out/usr/share/acrn/samples/nuc/acrn.conf ;\
fi


FROM scratch
ENTRYPOINT []
CMD []
COPY --from=kernel-build /out/ /
