# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-dom0-ztools:253a855cd711087887e06f9879358c76a9648c9c AS dom0
FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 AS build
ENV BUILD_PKGS="gcc g++ autoconf automake libtool make openssl-dev libtasn1-dev \
    json-glib-dev gnutls bash expect gawk socat libseccomp-dev gmp-dev \
    musl-utils autoconf-archive git json-c json-c-dev libcurl curl-dev \
    patch go protobuf-dev"
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
# This poinst to the latest commit that implements state backup functionality.
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
RUN ./bootstrap && \
    ./configure && \
    make -j$(nproc)
RUN cp lib/.libs/libcommon.so* /out/usr/lib/
RUN cp tools/.libs/tpm2 /out/usr/bin/
RUN strip --strip-unneeded /out/usr/lib/*.so*

# Build vtpm
WORKDIR /vtpm-build
COPY swtpm-vtpm/src/ /vtpm-build/.
COPY swtpm-vtpm/ /vtpm-build/.
ARG GOPKGVERSION
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# hadolint ignore=SC2046
RUN echo "Running go vet" && go vet ./... && echo "Running go fmt" && \
    ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
    if [ -n "$ERR" ] ; then echo "go fmt Failed - ERR: $ERR"; exit 1 ; fi
RUN GO111MODULE=on CGO_ENABLED=0 go build -ldflags "-s -w -X=main.Version=${GOPKGVERSION}" \
    -mod=vendor -o /out/usr/bin/vtpm .

# Build ptpm
WORKDIR /ptpm-build
ADD ptpm/ /ptpm-build
RUN make -j$(nproc) && cp ptpm /out/usr/bin/
RUN strip --strip-unneeded /out/usr/bin/ptpm

# remove static libraries and libtool libraries
RUN find /out/usr/lib/ -name '*.la' -delete
RUN find /out/usr/lib/ -name '*.a' -delete

FROM scratch
COPY --from=build /out/ /
COPY init.sh /usr/bin/
COPY --from=dom0 /etc/group /etc/group
COPY --from=dom0 /etc/passwd /etc/passwd
RUN mkdir /home && chown vtpm:vtpm /home
WORKDIR /home
ENTRYPOINT []
CMD ["/usr/bin/init.sh"]
