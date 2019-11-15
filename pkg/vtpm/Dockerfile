#There are four parts:
# a) building tpm2-tss
# b) building tpm2-tools
# c) building the vtpm server from local source
# d) extracting only required bits from tpm2-tss and tpm2-tools
#    and the server

#We need autoconf-archive from 3.8+, to satisfy autoconf
#autoconf-archive is not available in 3.8
FROM alpine:3.10 as alpine-3.10
RUN apk add --no-cache autoconf-archive=2019.01.06-r0

#We need curl bits, to satisfy tpm2-tools make
FROM alpine:3.8 as curl-dev-bits
RUN apk add --no-cache curl-dev=7.61.1-r3

#Build TPM2-TSS and TPM2-TOOLS
FROM alpine:3.8 as build
RUN apk add --no-cache linux-headers=4.4.6-r2 git=2.18.1-r0 \
                          gcc=6.4.0-r9 g++=6.4.0-r9 autoconf=2.69-r2 \
                          automake=1.16.1-r0 libtool=2.4.6-r5 \
                          doxygen=1.8.14-r0 make=4.2.1-r2 \
                          openssl-dev=1.0.2t-r0 protobuf-dev=3.5.2-r0

WORKDIR /
COPY --from=alpine-3.10 /usr/share/aclocal/ /usr/share/aclocal/
RUN git clone --branch=2.3.1 https://github.com/tpm2-software/tpm2-tss
WORKDIR /tpm2-tss
RUN ./bootstrap && \
    ./configure --disable-dependency-tracking && \
    make && \
    make install

WORKDIR /
RUN git clone --branch=4.0.1-rc0 https://github.com/tpm2-software/tpm2-tools
WORKDIR /tpm2-tools

#There is a known issue: curl-dev and openssl-dev don't go together,
#due to conflict between openssl-dev and libressl-dev(from curl-dev).
#Refer: https://bugs.alpinelinux.org/issues/8939. Also, ./configure
#expects package curl-dev to be present. Hence doing the steps below.

RUN apk del openssl-dev
RUN apk add --no-cache curl-dev=7.61.1-r3
RUN ./bootstrap && \
    ./configure

RUN apk del curl-dev
RUN apk add --no-cache openssl-dev=1.0.2t-r0
COPY --from=curl-dev-bits /usr/include/curl /usr/include/curl
COPY --from=curl-dev-bits /usr/lib/libcurl.so /usr/lib/libcurl.so
RUN make

#The vTPM server
COPY ./ /vtpm_server
WORKDIR /vtpm_server
RUN make

#Pull a selected set of artifacts into the final stage.
FROM alpine:3.8
RUN apk add --no-cache openssl=1.0.2t-r0 protobuf=3.5.2-r0

COPY --from=build /usr/local/lib/libtss2-tctildr.so.0 /usr/local/lib
COPY --from=build /usr/local/lib/libtss2-rc.so.0 /usr/local/lib
COPY --from=build /usr/local/lib/libtss2-mu.so.0 /usr/local/lib
COPY --from=build /usr/local/lib/libtss2-esys.so.0 /usr/local/lib
COPY --from=build /usr/local/lib/libtss2-sys.so.0.0.0 /usr/local/lib
COPY --from=build /usr/local/lib/libtss2-sys.so.0 /usr/local/lib
COPY --from=build /usr/local/lib/libtss2-tcti-device.so.0 /usr/local/lib
COPY --from=build /tpm2-tools/tools/tpm2_createek /usr/bin/
COPY --from=build /tpm2-tools/tools/tpm2_createak /usr/bin/
COPY --from=build /tpm2-tools/tools/tpm2_createprimary /usr/bin/
COPY --from=build /tpm2-tools/tools/tpm2_getcap /usr/bin/
COPY --from=build /tpm2-tools/tools/tpm2_sign /usr/bin/
COPY --from=build /tpm2-tools/tools/tpm2_verifysignature /usr/bin/
COPY --from=build /tpm2-tools/tools/tpm2_evictcontrol /usr/bin/
COPY --from=build /tpm2-tools/tools/tpm2_import /usr/bin/
COPY --from=build /tpm2-tools/tools/tpm2_load /usr/bin/
COPY --from=build /tpm2-tools/tools/tpm2_hmac /usr/bin/
COPY --from=build /vtpm_server/vtpm_server /usr/bin/
COPY init.sh /usr/bin/
ENTRYPOINT []
WORKDIR /
CMD ["/usr/bin/init.sh"]
