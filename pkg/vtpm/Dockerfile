# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023-2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-dom0-ztools:926579af8ae3f33aec8f4257bfbd7da4ae5a8881  AS dom0

# ===========================================================================
# C builds (libtpms, swtpm, tpm2-tss, tpm2-tools, ptpm)
# These use autoconf/automake with many -dev dependencies, so for now they
# remain under QEMU emulation when cross-building.
# ===========================================================================
FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build-c
# iproute2: swtpm's configure insists on ss or netstat for its tests;
# libltdl-dev: the ltdl.m4 macros tpm2-tss's configure.ac uses
ENV BUILD_PKGS="gcc g++ autoconf automake libtool make libssl-dev libtasn1-6-dev \
    libjson-glib-dev libgnutls28-dev gnutls-bin bash expect gawk socat libseccomp-dev libgmp-dev \
    autoconf-archive git libjson-c-dev libcurl4-openssl-dev pkg-config \
    patch libprotobuf-dev protobuf-compiler iproute2 libltdl-dev"
ENV PKGS="libseccomp2 libcurl4t64 libstdc++6 libprotobuf32t64 libglib2.0-0t64 libffi8 libjson-c5 libjson-glib-1.0-0 libgnutls30t64 libtasn1-6"
RUN eve-ubuntu-deploy.sh

# build libtpms, it is needed by swtpm
WORKDIR /libtpms
ADD https://github.com/stefanberger/libtpms.git#v0.10.0 /libtpms
# their configure appends -Werror; gcc 15 makes memchr/strchr const-correct
RUN CFLAGS="-g -O2 -Wno-error=discarded-qualifiers" ./autogen.sh --prefix=/usr --with-tpm2
RUN make -j$(nproc)
RUN make -j$(nproc) install
RUN cp /usr/lib/libtpms.so.* /out/usr/lib/
RUN strip --strip-unneeded /out/usr/lib/libtpms.so.*
# Register libtpms in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n libtpms -v 0.10.0 -l BSD-3-Clause \
    -u https://github.com/stefanberger/libtpms \
    -d "TPM 2.0 emulation library (built from source)"

# build swtpm
WORKDIR /swtpm
# This points to the latest commit that implements state backup functionality.
# TODO: revert this when there is a new release in swtpm
ADD https://github.com/stefanberger/swtpm.git#732bbd6ad3a52b9552b5a1620e03a9f6449a1aab /swtpm
RUN CFLAGS="-g -O2 -Wno-error=discarded-qualifiers" ./autogen.sh --prefix=/out/usr
RUN make -j$(nproc)
RUN src/swtpm/swtpm socket --tpm2 --print-capabilities | grep "tpmstate-dir-backend-opt-backup"
RUN make -j$(nproc) install
RUN cp /out/usr/lib/swtpm/* /out/usr/lib/
RUN strip --strip-unneeded /out/usr/lib/swtpm/*.so*
# Register swtpm in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n swtpm -v 732bbd6a -l BSD-3-Clause \
    -u https://github.com/stefanberger/swtpm \
    -d "TPM emulator (built from source)"

# build tpm2-tss, it is needed by tpm2-tools
WORKDIR /tpm2-tss
ADD --keep-git-dir=true https://github.com/tpm2-software/tpm2-tss.git#4.0.1 /tpm2-tss
RUN ./bootstrap && \
    ./configure --disable-dependency-tracking && \
    make -j$(nproc) && \
    make install
RUN cp /usr/local/lib/libtss2* /out/usr/lib/
RUN strip --strip-unneeded /out/usr/lib/libtss2*.so*
# Register tpm2-tss in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n tpm2-tss -v 4.0.1 -l BSD-2-Clause \
    -u https://github.com/tpm2-software/tpm2-tss \
    -d "TPM2 Software Stack (built from source)"

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
# Register tpm2-tools in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n tpm2-tools -v 5.5 -l BSD-3-Clause \
    -u https://github.com/tpm2-software/tpm2-tools \
    -d "TPM2 command line tools (built from source)"

# Build ptpm (C++)
WORKDIR /ptpm-build
ADD ptpm/ /ptpm-build
RUN make -j$(nproc) && cp ptpm /out/usr/bin/
RUN strip --strip-unneeded /out/usr/bin/ptpm

# remove static libraries and libtool libraries
RUN find /out/usr/lib/ -name '*.la' -delete
RUN find /out/usr/lib/ -name '*.a' -delete

RUN rm -f /out/usr/lib/libprotoc.so*

# ===========================================================================
# Go build (vtpm)
# Go has first-class cross-compilation support, so we run this natively on
# the build host using --platform=$BUILDPLATFORM and set GOARCH to target.
# This avoids QEMU, which is known to deadlock on go vet / go build.
# ===========================================================================
# hadolint ignore=DL3029
FROM --platform=$BUILDPLATFORM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build-go
ARG TARGETARCH

WORKDIR /vtpm-build
COPY swtpm-vtpm/src/ /vtpm-build/.
COPY swtpm-vtpm/ /vtpm-build/.
ARG GOPKGVERSION
SHELL ["/bin/bash", "-eo", "pipefail", "-c"]
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
# hadolint ignore=DL3008
RUN apt-get -y install --no-install-recommends gcc libc6-dev \
    libseccomp2 libglib2.0-0t64 libjson-glib-1.0-0 libgnutls30t64 libtasn1-6 libjson-c5 libffi8
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
RUN mkdir -p /home && chown vtpm:vtpm /home
WORKDIR /home
ENTRYPOINT []
CMD ["/usr/bin/init.sh"]
