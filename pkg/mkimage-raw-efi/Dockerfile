FROM alpine:3.7

RUN apk add --no-cache \
  mtools \
  dosfstools \
  libarchive-tools \
  sgdisk \
  e2fsprogs \
  util-linux \
  coreutils

WORKDIR /
COPY make-raw install /
COPY /efi-files /efifs

RUN echo "mtools_skip_check=1" >> /etc/mtools.conf

ENTRYPOINT [ "/make-raw" ]
