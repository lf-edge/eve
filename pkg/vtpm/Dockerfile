# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

#There are four parts:
# a) building tpm2-tss
# b) building tpm2-tools
# c) building the vtpm server from local source
# d) extracting only required bits from tpm2-tss and tpm2-tools
#    and the server

#Build TPM2-TSS and TPM2-TOOLS
FROM lfedge/eve-alpine:c114cf1d3ea51534f061f9aa949beb6ac5c12fb3 as build
ENV BUILD_PKGS linux-headers git gcc g++ autoconf automake libtool doxygen make \
               openssl-dev protobuf-dev gnupg curl-dev patch json-c json-c-dev \
               util-linux-dev libcurl curl-dev
ENV PKGS alpine-baselayout musl-utils libcurl
RUN eve-alpine-deploy.sh

WORKDIR /
ADD https://ftpmirror.gnu.org/autoconf-archive/autoconf-archive-2019.01.06.tar.xz /autoconf-archive-2019.01.06.tar.xz
ADD https://ftpmirror.gnu.org/autoconf-archive/autoconf-archive-2019.01.06.tar.xz.sig /autoconf-archive-2019.01.06.tar.xz.sig
ADD http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x99089D72 /import-key.asc
RUN gpg2 -q --import /import-key.asc && \
    gpg2 -q --verify autoconf-archive-2019.01.06.tar.xz.sig

#Build autoconf-archive
RUN tar -xvf autoconf-archive-2019.01.06.tar.xz
WORKDIR /autoconf-archive-2019.01.06
RUN ./configure --datarootdir=/usr/share/ && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && make install

WORKDIR /tpm2-tss
ADD --keep-git-dir=true https://github.com/tpm2-software/tpm2-tss.git#4.0.1 /tpm2-tss
RUN ./bootstrap && \
    ./configure --disable-dependency-tracking && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && \
    make install

WORKDIR /tpm2-tools
ADD --keep-git-dir=true https://github.com/tpm2-software/tpm2-tools.git#5.5 /tpm2-tools
COPY patch-tpm2-tools.diff .
RUN patch -p1 < patch-tpm2-tools.diff
RUN ./bootstrap && ./configure && make -j "$(getconf _NPROCESSORS_ONLN)"

RUN mkdir -p /out/usr/local/lib
RUN cp lib/.libs/libcommon.so* /out/usr/local/lib/
RUN cp tools/.libs/tpm2 /out/usr/bin/

#The vTPM server
COPY ./ /vtpm_server
WORKDIR /vtpm_server
RUN make -j "$(getconf _NPROCESSORS_ONLN)" && cp vtpm_server /out/usr/bin/

# install dependencies
WORKDIR /usr/lib
RUN cp libstdc++.so.6 libgcc_s.so.1 libprotobuf.so.29.0.1 /out/usr/lib/
RUN ln -s libprotobuf.so.29.0.1 /out/usr/lib/libprotobuf.so.29
WORKDIR /usr/local/lib
RUN cp libtss2-tctildr.so.0 libtss2-rc.so.0 libtss2-mu.so.0 libtss2-esys.so.0 \
       libtss2-sys.so.1 libtss2-tcti-device.so.0 libtss2-tcti-device.so.0.0.0 \
       /out/usr/local/lib/

#Pull a selected set of artifacts into the final stage.
FROM scratch

COPY --from=build /out/ /
COPY init.sh /usr/bin/
ENTRYPOINT []
WORKDIR /
CMD ["/usr/bin/init.sh"]
