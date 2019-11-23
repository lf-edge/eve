FROM alpine:3.8 as kernel-build
ENV GIT_HTTP=y
# hadolint ignore=DL3018
RUN apk add --no-cache \
    gcc make libc-dev dev86 xz-dev perl bash python-dev \
    gettext iasl util-linux-dev ncurses-dev glib-dev \
    pixman-dev libaio-dev yajl-dev argp-standalone \
    linux-headers git patch texinfo curl tar libcap-dev \
    attr-dev flex bison cmake g++ nasm util-linux

# FIXME: this is really ugly -- we need to figure out xen tools dependencies
RUN [ "$(uname -m)" = "aarch64" ] && apk add --no-cache dtc-dev || :

# Alpine linux defines all 64bit integer types as long. Patch
# /usr/include/bits/alltypes.h to fix compilation with -m32
WORKDIR /
COPY alpine.patch /
RUN patch -p1 < alpine.patch

ENV XEN_VERSION 4.13.0-rc2
ENV XEN_SOURCE=https://downloads.xenproject.org/release/xen/${XEN_VERSION}/xen-${XEN_VERSION}.tar.gz

# Download and verify xen
#TODO: verify Xen
RUN \
    [ -f "$(basename ${XEN_SOURCE})" ] || curl -fsSLO "${XEN_SOURCE}" && \
    tar --absolute-names -xz < "$(basename ${XEN_SOURCE})" && mv "/xen-${XEN_VERSION}" /xen

# Apply local patches
COPY patches-${XEN_VERSION} /patches
WORKDIR /xen
RUN set -e && for patch in /patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p1 < "$patch"; \
    done

RUN mkdir -p /out

COPY gmp.patch /xen/stubdom
WORKDIR /xen
RUN [ "$(uname -m)" = "x86_64" ] && FEATURES="--enable-stubdom --enable-vtpm-stubdom --enable-vtpmmgr-stubdom" ;\
    ./configure --prefix=/usr --disable-xen --disable-qemu-traditional --disable-docs --enable-9pfs --enable-ovmf $FEATURES
RUN make && make dist
RUN dist/install.sh /out

# Filter out a few things that we don't currently need
RUN rm /out/usr/share/qemu-xen/qemu/edk2-*

FROM scratch
ENTRYPOINT []
CMD []
COPY --from=kernel-build /out/ /
