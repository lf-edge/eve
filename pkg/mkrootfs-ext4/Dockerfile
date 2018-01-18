FROM linuxkit/alpine:77287352db68b442534c0005edd6ff750c8189f3 AS make-img

RUN \
  apk update && apk upgrade && \
  apk add --no-cache \
  dosfstools \
  libarchive-tools \
  binutils \
  mtools \
  sfdisk \
  sgdisk \
  xfsprogs \
  e2fsprogs \
  util-linux \
  coreutils \
  multipath-tools \
  && true

COPY . .

ENTRYPOINT [ "/make-rootfs" ]
