FROM alpine:3.12 as build

ENV KVMTOOL_VERSION=90b2d3adadf218dfc6bdfdfcefe269843360223c

ADD  https://git.kernel.org/pub/scm/linux/kernel/git/will/kvmtool.git/snapshot/kvmtool-${KVMTOOL_VERSION}.tar.gz /kvmtool.tar.gz
COPY 0001-Makefile-Update-bfd-detection.patch /

RUN apk add --no-cache       \
      gcc=9.3.0-r2           \
      make=4.3-r0            \
      libc-dev=0.7.2-r3      \
      binutils-dev=2.34-r1   \
      patch=2.7.6-r6         \
      libaio-dev=0.3.112-r1  \
      zlib-dev=1.2.11-r3     \
      zlib-static=1.2.11-r3  \
      linux-headers=5.4.5-r1 \
      libvncserver-dev=0.9.13-r1

RUN tar xzvf kvmtool.tar.gz > /dev/null 2>&1 ;\
    mv kvmtool-${KVMTOOL_VERSION} kvmtool

WORKDIR /kvmtool

RUN patch -p1 < /0001-Makefile-Update-bfd-detection.patch ;\
    make && make install DESTDIR=/usr HOME=

FROM alpine:3.12

RUN apk add --no-cache \
            libvncserver=0.9.13-r1 \
            libaio=0.3.112-r1

COPY --from=build /usr/bin/lkvm /usr/bin/lkvm
RUN ln -sf lkvm /usr/bin/vm
RUN ldd /usr/bin/lkvm

#ENTRYPOINT []
#CMD ["/usr/sbin/vm",]

