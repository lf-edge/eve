FROM golang:1.12.4-alpine

RUN apk add --no-cache ca-certificates gcc libc6-compat gnupg make automake wget git coreutils cpio squashfs-tools autoconf file xz patch bc acl-dev openssl-dev at-spi2-core python pkgconfig zlib-dev musl-dev pixman libcap libfdt bash

RUN git clone https://github.com/rkt/rkt.git
WORKDIR rkt
RUN git reset --hard tags/v1.26.0
COPY rkt-patch.diff patch.diff
RUN patch -p1 < patch.diff

RUN ./autogen.sh && ./configure --enable-sdjournal=no --disable-tpm --with-stage1-flavors=host && make
