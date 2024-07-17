# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

#There are four parts:
# a) building tpm2-tss
# b) building tpm2-tools
# c) building the vtpm server from local source
# d) extracting only required bits from tpm2-tss and tpm2-tools
#    and the server

FROM lfedge/eve-dom0-ztools:7de883dd3e1da400ddf28b109dcfd68a3641bf79 as dom0
FROM lfedge/eve-alpine:e34284a8dd69c9c5ba7c52cd7b7d08fc2db1e0ac as build
ENV BUILD_PKGS linux-headers git gcc g++ autoconf automake libtool doxygen make \
               openssl-dev libprotobuf protobuf-dev gnupg curl-dev patch json-c json-c-dev \
               util-linux-dev libcurl curl-dev autoconf-archive bash
ENV PKGS alpine-baselayout musl-utils libcurl libprotobuf
RUN eve-alpine-deploy.sh

#Build TPM2-TSS and TPM2-TOOLS
WORKDIR /tpm2-tss
ADD --keep-git-dir=true https://github.com/tpm2-software/tpm2-tss.git#4.0.1 /tpm2-tss
RUN ./bootstrap && \
    CFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3" ./configure --disable-dependency-tracking && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && \
    make install

WORKDIR /tpm2-tools
ADD --keep-git-dir=true https://github.com/tpm2-software/tpm2-tools.git#5.5 /tpm2-tools
COPY patch-tpm2-tools.diff .
RUN patch -p1 < patch-tpm2-tools.diff
RUN ./bootstrap && \
    CFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3" ./configure && \
    make -j "$(getconf _NPROCESSORS_ONLN)"

RUN mkdir -p /out/usr/local/lib
RUN cp lib/.libs/libcommon.so* /out/usr/local/lib/
RUN cp tools/.libs/tpm2 /out/usr/bin/

#The vTPM server
COPY ./ /vtpm_server
WORKDIR /vtpm_server
RUN mkdir -p /out/usr/bin && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && cp vtpm_server /out/usr/bin/

# install dependencies
WORKDIR /usr/local/lib
RUN cp libtss2-tctildr.so.0 libtss2-rc.so.0 libtss2-mu.so.0 libtss2-esys.so.0 \
       libtss2-sys.so.1 libtss2-tcti-device.so.0 libtss2-tcti-device.so.0.0.0 \
       /out/usr/local/lib/

# setup vtpm permissions
WORKDIR /
# copy group/passwd from dom0 image to be able to use names insdead of ids.
COPY --from=dom0 /etc/group /etc/group
COPY --from=dom0 /etc/passwd /etc/passwd
RUN mkdir /out/jail && chown vtpm:vtpm /out/jail

#Pull a selected set of artifacts into the final stage.
FROM scratch
COPY --from=build /out/ /
COPY init.sh /usr/bin/
ENTRYPOINT []
WORKDIR /
CMD ["/usr/bin/init.sh"]
