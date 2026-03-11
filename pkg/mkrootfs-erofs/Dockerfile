FROM lfedge/eve-alpine:745ae9066273c73b0fd879c4ba4ff626a8392d04-dirty-fe81aa7 AS build

ARG EROFS_UTILS_VERSION=v1.7.1
ARG LZ4_VERSION=v1.9.4

ENV BUILD_PKGS autoconf automake libtool gcc libc-dev linux-headers make \
    pkgconfig util-linux-dev zlib-dev
ENV PKGS dosfstools libarchive-tools binutils mtools sfdisk sgdisk \
    xfsprogs e2fsprogs util-linux coreutils multipath-tools libuuid zlib
RUN eve-alpine-deploy.sh

# Build lz4 from source (eve-alpine ships no -dev packages).
ADD --keep-git-dir=true https://github.com/lz4/lz4.git#${LZ4_VERSION} /lz4
RUN make -C /lz4 -j "$(getconf _NPROCESSORS_ONLN)" lib && \
    make -C /lz4 install PREFIX=/usr && \
    test -f /usr/include/lz4.h && test -f /usr/lib/liblz4.so

ADD --keep-git-dir=true https://github.com/erofs/erofs-utils.git#${EROFS_UTILS_VERSION} /erofs-utils
WORKDIR /erofs-utils
RUN ./autogen.sh && \
    ./configure --prefix=/usr && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && \
    make DESTDIR=/out install && \
    test -x /out/usr/bin/mkfs.erofs

# Copy lz4 shared lib into final image for runtime.
RUN cp /usr/lib/liblz4.so* /out/usr/lib/

COPY . /out/

FROM scratch
COPY --from=build /out/ /
ENTRYPOINT ["/make-rootfs"]
