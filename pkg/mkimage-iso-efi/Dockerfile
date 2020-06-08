FROM linuxkit/alpine:ad35b6ddbc70faa07e59a9d7dee7707c08122e8d AS make-img

RUN mkdir -p /out/etc/apk /out/boot && cp -r /etc/apk/* /out/etc/apk/
RUN apk add --no-cache --initdb -p /out \
  dosfstools \
  libarchive-tools \
  binutils \
  mtools \
  xorriso
RUN echo "mtools_skip_check=1" >> /out/etc/mtools.conf

FROM scratch
COPY --from=make-img /out /
COPY . /
WORKDIR /
ENTRYPOINT [ "/make-efi" ]
