# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023-2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-dom0-ztools:12f3be8183942a1134241414bc265f624dbaad51 AS dom0

# ===========================================================================
# C builds (libtpms, swtpm, tpm2-tss, tpm2-tools, ptpm)
# These use autoconf/automake with many -dev dependencies, so for now they
# remain under QEMU emulation when cross-building.
# ===========================================================================
FROM lfedge/eve-alpine:1f744180283ffb4eabcc3862531aeacf1de886b3 AS build-c
ENV BUILD_PKGS="gcc g++ autoconf automake libtool make openssl-dev libtasn1-dev \
    json-glib-dev gnutls bash expect gawk socat libseccomp-dev gmp-dev \
    musl-utils autoconf-archive git json-c json-c-dev libcurl curl-dev \
    patch protobuf-dev"
ENV PKGS="libseccomp libcurl libstdc++ libprotobuf pcre libintl glib libffi json-c json-glib"
RUN eve-alpine-deploy.sh

# build libtpms, it is needed by swtpm
WORKDIR /libtpms
ADD https://github.com/stefanberger/libtpms.git#v0.10.0 /libtpms
RUN ./autogen.sh --prefix=/usr --with-tpm2
RUN make -j$(nproc)
RUN make -j$(nproc) install
RUN cp /usr/lib/libtpms.so.* /out/usr/lib/
RUN strip --strip-unneeded /out/usr/lib/libtpms.so.*

# build swtpm
WORKDIR /swtpm
# This points to the latest commit that implements state backup functionality.
# TODO: revert this when there is a new release in swtpm
ADD https://github.com/stefanberger/swtpm.git#732bbd6ad3a52b9552b5a1620e03a9f6449a1aab /swtpm
RUN ./autogen.sh --prefix=/out/usr
RUN make -j$(nproc)
RUN src/swtpm/swtpm socket --tpm2 --print-capabilities | grep "tpmstate-dir-backend-opt-backup"
RUN make -j$(nproc) install
RUN cp /out/usr/lib/swtpm/* /out/usr/lib/
RUN strip --strip-unneeded /out/usr/lib/swtpm/*.so*

# build tpm2-tss, it is needed by tpm2-tools
WORKDIR /tpm2-tss
ADD --keep-git-dir=true https://github.com/tpm2-software/tpm2-tss.git#4.0.1 /tpm2-tss
RUN ./bootstrap && \
    ./configure --disable-dependency-tracking && \
    make -j$(nproc) && \
    make install
RUN cp /usr/local/lib/libtss2* /out/usr/lib/
RUN strip --strip-unneeded /out/usr/lib/libtss2*.so*

# build tpm2-tools, it is needed by ptpm
WORKDIR /tpm2-tools
ADD --keep-git-dir=true https://github.com/tpm2-software/tpm2-tools.git#5.5 /tpm2-tools
COPY patches/ /patches/
RUN for patch in /patches/*.patch; do \
    echo "Applying $patch"; \
    patch -d /tpm2-tools -p1 < "$patch" || exit 1 ; \
    done
RUN ./bootstrap
RUN ./configure CFLAGS="-Wno-error"
RUN make -j$(nproc)
RUN cp lib/.libs/libcommon.so* /out/usr/lib/
RUN cp tools/.libs/tpm2 /out/usr/bin/
RUN strip --strip-unneeded /out/usr/lib/*.so*

# Build ptpm (C++)
WORKDIR /ptpm-build
ADD ptpm/ /ptpm-build
RUN make -j$(nproc) && cp ptpm /out/usr/bin/
RUN strip --strip-unneeded /out/usr/bin/ptpm

# remove static libraries and libtool libraries
RUN find /out/usr/lib/ -name '*.la' -delete
RUN find /out/usr/lib/ -name '*.a' -delete

RUN rm /out/usr/lib/libprotoc.so*

# ===========================================================================
# Go build (vtpm)
# Go has first-class cross-compilation support, so we run this natively on
# the build host using --platform=$BUILDPLATFORM and set GOARCH to target.
# This avoids QEMU, which is known to deadlock on go vet / go build.
# ===========================================================================
# hadolint ignore=DL3029
FROM --platform=$BUILDPLATFORM lfedge/eve-alpine:1f744180283ffb4eabcc3862531aeacf1de886b3 AS build-go
ARG TARGETARCH

WORKDIR /vtpm-build
COPY swtpm-vtpm/src/ /vtpm-build/.
COPY swtpm-vtpm/ /vtpm-build/.
ARG GOPKGVERSION
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# hadolint ignore=SC2046
RUN echo "Running go vet" && GOARCH=${TARGETARCH} go vet ./... && echo "Running go fmt" && \
    ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
    if [ -n "$ERR" ] ; then echo "go fmt Failed - ERR: $ERR"; exit 1 ; fi
RUN GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -ldflags "-s -w -X=main.Version=${GOPKGVERSION}" \
    -mod=vendor -o /out/usr/bin/vtpm .

FROM build-go AS test
# -race requires cgo, which needs a C compiler and libc headers.
# swtpm needs its runtime shared libraries.
RUN apk add --no-cache gcc musl-dev \
    libseccomp glib json-glib gnutls libtasn1 json-c libffi
# copy swtpm, its modules, and libtpms from the C build stage
COPY --from=build-c /out/usr/bin/swtpm /usr/bin/swtpm
COPY --from=build-c /out/usr/lib/ /usr/lib/
WORKDIR /vtpm-build
COPY swtpm-vtpm/src/ /vtpm-build/.
COPY swtpm-vtpm/ /vtpm-build/.

# ===========================================================================
# Final image
# ===========================================================================
FROM scratch
COPY --from=build-c /out/ /
COPY --from=build-go /out/usr/bin/vtpm /usr/bin/vtpm
COPY init.sh /usr/bin/
COPY --from=dom0 /etc/group /etc/group
COPY --from=dom0 /etc/passwd /etc/passwd
RUN mkdir /home && chown vtpm:vtpm /home
WORKDIR /home
ENTRYPOINT []
CMD ["/usr/bin/init.sh"]
