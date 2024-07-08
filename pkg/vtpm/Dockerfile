# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM shahzededa/eve-alpine:latest as build
ENV BUILD_PKGS gcc g++ autoconf automake libtool make openssl-dev libtasn1-dev \
               json-glib-dev gnutls bash expect gawk socat libseccomp-dev gmp-dev musl-utils
ENV PKGS alpine-baselayout musl-utils glib gmp gnutls libtasn1 libseccomp musl \
         strace libcrypto3 json-glib gdb
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

#Pull a selected set of artifacts into the final stage.
FROM scratch
COPY --from=build /out /
COPY init.sh /usr/bin/
ENTRYPOINT []
WORKDIR /

CMD ["/usr/bin/init.sh"]
