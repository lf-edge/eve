FROM alpine:3.6 as kernel-build
RUN apk add --no-cache \
    	    gcc make libc-dev dev86 xz-dev perl bash python-dev \
	    gettext iasl util-linux-dev ncurses-dev glib-dev \
	    pixman-dev libaio-dev yajl-dev argp-standalone \
	    linux-headers git patch texinfo curl tar

# FIXME: this is really ugly -- we need to figure out xen tools dependencies
RUN [ `uname -m` = "aarch64" ] && apk add --no-cache dtc-dev || :

# Alpine linux defines all 64bit integer types as long. Patch
# /usr/include/bits/alltypes.h to fix compilation with -m32
WORKDIR /
COPY alpine.patch /
RUN patch -p1 < alpine.patch

ENV XEN_VERSION 4.11.0
ENV XEN_SOURCE=https://downloads.xenproject.org/release/xen/${XEN_VERSION}/xen-${XEN_VERSION}.tar.gz

# Download and verify xen
#TODO: verify Xen
RUN \
    [ -f xen-${XEN_VERSION}.tar.gz ] || curl -fsSLO ${XEN_SOURCE} && \
    gzip -d xen-${XEN_VERSION}.tar.gz && \
    cat xen-${XEN_VERSION}.tar | tar --absolute-names -x && mv /xen-${XEN_VERSION} /xen

# Apply local patches
COPY patches-${XEN_VERSION} /patches
WORKDIR /xen
RUN set -e && for patch in /patches/*.patch; do \
        echo "Applying $patch"; \
        patch -p1 < "$patch"; \
    done

RUN mkdir -p /out

WORKDIR /xen
RUN ./configure --prefix=/usr --disable-xen --disable-qemu-traditional --disable-docs --disable-stubdom
RUN make && make dist
RUN dist/install.sh /out

FROM scratch
ENTRYPOINT []
CMD []
COPY --from=kernel-build /out/ /
