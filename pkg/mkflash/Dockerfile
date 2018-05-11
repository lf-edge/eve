FROM alpine:3.7

RUN apk add --no-cache \
  mtools \
  dosfstools \
  libarchive-tools \
  sgdisk \
  coreutils

WORKDIR /
COPY make-flash .
COPY /efi-files /efifs

ENTRYPOINT [ "/make-flash" ]
