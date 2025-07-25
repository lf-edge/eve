FROM lfedge/eve-alpine:523254c1b0728948a16a02115eb817f27c00977f AS build

ENV BUILD_PKGS patch curl make gcc perl util-linux-dev git mtools linux-headers musl-dev xz-dev elfutils-dev libbz2
ENV PKGS xz-libs util-linux elfutils-dev libbz2

RUN eve-alpine-deploy.sh

# Build kexec-tools
ENV KEXEC_VERSION=2.0.23
WORKDIR /tmp/kexec/kexec-tools-${KEXEC_VERSION}
ADD https://mirrors.edge.kernel.org/pub/linux/utils/kernel/kexec/kexec-tools-2.0.23.tar.gz /tmp/kexec/kexec-tools.tgz
RUN tar -C .. -xzvf ../kexec-tools.tgz && rm -f ../kexec-tools.tgz
RUN ./configure --prefix /usr && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && \
    make DESTDIR=/out install

FROM scratch
COPY --from=build /out /
