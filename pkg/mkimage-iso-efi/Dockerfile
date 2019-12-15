FROM linuxkit/alpine:ad35b6ddbc70faa07e59a9d7dee7707c08122e8d AS make-img

RUN \
  apk update && apk upgrade && \
  apk add --no-cache \
  dosfstools \
  libarchive-tools \
  binutils \
  mtools \
  xorriso \
  && true

COPY . .

RUN echo "mtools_skip_check=1" >> /etc/mtools.conf

ENTRYPOINT [ "/make-efi" ]
