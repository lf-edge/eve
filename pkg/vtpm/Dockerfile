# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM shahzededa/eve-alpine:latest as build
ENV BUILD_PKGS gcc g++ autoconf automake libtool make openssl-dev libtasn1-dev \
               json-glib-dev gnutls bash expect gawk socat libseccomp-dev gmp-dev \
               musl-utils autoconf-archive git json-c json-c-dev libcurl curl-dev \
               patch go
ENV PKGS libseccomp socat libcurl
RUN eve-alpine-deploy.sh

ADD https://github.com/stefanberger/libtpms.git#v0.9.6 /libtpms
WORKDIR /libtpms
RUN ./autogen.sh --prefix=/usr --with-tpm2
RUN make -j$(nproc)
RUN make -j$(nproc) install
RUN cp /usr/lib/libtpms.so.* /out/usr/lib/

ADD https://github.com/stefanberger/swtpm.git#v0.9.0 /swtpm
WORKDIR /swtpm
RUN ./autogen.sh --prefix=/out/usr
RUN make -j$(nproc)
RUN make -j$(nproc) install
RUN cp /out/usr/lib/swtpm/* /out/usr/lib/

WORKDIR /tpm2-tss
ADD --keep-git-dir=true https://github.com/tpm2-software/tpm2-tss.git#4.0.1 /tpm2-tss
RUN ./bootstrap && \
    ./configure --disable-dependency-tracking && \
    make -j$(nproc) && \
    make install
RUN cp /usr/local/lib/libtss2* /out/usr/lib/

WORKDIR /tpm2-tools
ADD --keep-git-dir=true https://github.com/tpm2-software/tpm2-tools.git#5.5 /tpm2-tools
COPY patch/patch-tpm2-tools.diff .
RUN patch -p1 < patch-tpm2-tools.diff
RUN ./bootstrap && \
    ./configure && \
    make -j$(nproc)
RUN cp lib/.libs/libcommon.so* /out/usr/lib/
RUN cp tools/.libs/tpm2 /out/usr/bin/

COPY src/  /build/.
COPY go.mod /build/.
COPY go.sum /build/.
COPY vendor /build/vendor
ARG GOPKGVERSION
WORKDIR /build
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# hadolint ignore=SC2046
RUN echo "Running go vet" && go vet ./... && echo "Running go fmt" && \
    ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
    if [ -n "$ERR" ] ; then echo "go fmt Failed - ERR: $ERR"; exit 1 ; fi
RUN GO111MODULE=on CGO_ENABLED=0 go build -ldflags "-s -w -X=main.Version=${GOPKGVERSION}" \
    -mod=vendor -o /out/usr/bin/vtpmd .

FROM scratch
COPY --from=build /out/ /
COPY init.sh /usr/bin/
RUN mkdir /home && chown 101:101 /home
WORKDIR /home
ENTRYPOINT []
CMD ["/usr/bin/init.sh"]
