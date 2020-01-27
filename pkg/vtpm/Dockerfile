#There are four parts:
# a) building tpm2-tss
# b) building tpm2-tools
# c) building the vtpm server from local source
# d) extracting only required bits from tpm2-tss and tpm2-tools
#    and the server

#Build TPM2-TSS and TPM2-TOOLS
FROM lfedge/eve-alpine:7f9eb149210025d124027b8c31d6e72fae726da9 as build
RUN apk add --no-cache linux-headers=4.18.13-r1 git=2.20.2-r0 \
                          gcc=8.3.0-r0 g++=8.3.0-r0 autoconf=2.69-r2 \
                          automake=1.16.1-r0 libtool=2.4.6-r5 \
                          doxygen=1.8.15-r0 make=4.2.1-r2 \
                          openssl-dev=1.1.1d-r2 protobuf-dev=3.6.1-r1 \
                          gnupg=2.2.19-r0 curl-dev=7.64.0-r3

WORKDIR /
RUN wget https://ftpmirror.gnu.org/autoconf-archive/autoconf-archive-2019.01.06.tar.xz && \
    wget https://ftpmirror.gnu.org/autoconf-archive/autoconf-archive-2019.01.06.tar.xz.sig && \
    gpg2 -q --keyserver keys.gnupg.net --recv-keys 99089D72 && \
    gpg2 -q --verify autoconf-archive-2019.01.06.tar.xz.sig

#Build autoconf-archive
RUN tar -xvf autoconf-archive-2019.01.06.tar.xz
WORKDIR /autoconf-archive-2019.01.06
RUN ./configure --datarootdir=/usr/share/ && \
    make && make install

WORKDIR /
RUN git clone --branch=2.3.1 https://github.com/tpm2-software/tpm2-tss
WORKDIR /tpm2-tss
RUN ./bootstrap && \
    ./configure --disable-dependency-tracking && \
    make && \
    make install

WORKDIR /
RUN git clone --branch=4.0.1-rc0 https://github.com/tpm2-software/tpm2-tools
WORKDIR /tpm2-tools
COPY patch-tpm2-tools.diff .
RUN patch -p1 < patch-tpm2-tools.diff && \
    ./bootstrap && ./configure && make

RUN mkdir /out
RUN cp lib/.libs/libcommon.so* /out/
RUN cp tools/.libs/tpm2_* /out/

#The vTPM server
COPY ./ /vtpm_server
WORKDIR /vtpm_server
RUN make

#Pull a selected set of artifacts into the final stage.
FROM alpine:3.9

COPY --from=build /usr/lib/libstdc++.so.6 /usr/lib
COPY --from=build /usr/lib/libgcc_s.so.1 /usr/lib
COPY --from=build /usr/lib/libprotobuf.so.17  /usr/lib/
COPY --from=build /usr/lib/libprotobuf.so.17.0.0 /usr/lib/
COPY --from=build /usr/local/lib/libtss2-tctildr.so.0 /usr/local/lib
COPY --from=build /usr/local/lib/libtss2-rc.so.0 /usr/local/lib
COPY --from=build /usr/local/lib/libtss2-mu.so.0 /usr/local/lib
COPY --from=build /usr/local/lib/libtss2-esys.so.0 /usr/local/lib
COPY --from=build /usr/local/lib/libtss2-sys.so.0.0.0 /usr/local/lib
COPY --from=build /usr/local/lib/libtss2-sys.so.0 /usr/local/lib
COPY --from=build /usr/local/lib/libtss2-tcti-device.so.0 /usr/local/lib
COPY --from=build /out/libcommon.so.0.0.0 /usr/local/lib
COPY --from=build /out/libcommon.so.0 /usr/local/lib
COPY --from=build /out/libcommon.so /usr/local/lib
COPY --from=build /out/tpm2_createek /usr/bin/
COPY --from=build /out/tpm2_createak /usr/bin/
COPY --from=build /out/tpm2_createprimary /usr/bin/
COPY --from=build /out/tpm2_getcap /usr/bin/
COPY --from=build /out/tpm2_sign /usr/bin/
COPY --from=build /out/tpm2_verifysignature /usr/bin/
COPY --from=build /out/tpm2_evictcontrol /usr/bin/
COPY --from=build /out/tpm2_import /usr/bin/
COPY --from=build /out/tpm2_load /usr/bin/
COPY --from=build /out/tpm2_hmac /usr/bin/
COPY --from=build /out/tpm2_hash /usr/bin/
COPY --from=build /out/tpm2_readpublic /usr/bin/
COPY --from=build /out/tpm2_activatecredential /usr/bin
COPY --from=build /out/tpm2_makecredential /usr/bin
COPY --from=build /out/tpm2_dictionarylockout /usr/bin
COPY --from=build /out/tpm2_startauthsession /usr/bin
COPY --from=build /out/tpm2_policysecret /usr/bin
COPY --from=build /out/tpm2_policypassword /usr/bin
COPY --from=build /out/tpm2_policycommandcode /usr/bin
COPY --from=build /out/tpm2_create /usr/bin
COPY --from=build /out/tpm2_loadexternal /usr/bin
COPY --from=build /out/tpm2_duplicate /usr/bin
COPY --from=build /out/tpm2_flushcontext /usr/bin
COPY --from=build /out/tpm2_rsadecrypt /usr/bin
COPY --from=build /vtpm_server/vtpm_server /usr/bin/
COPY init.sh /usr/bin/
ENTRYPOINT []
WORKDIR /
CMD ["/usr/bin/init.sh"]
