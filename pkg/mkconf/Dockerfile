FROM linuxkit/alpine:77287352db68b442534c0005edd6ff750c8189f3
RUN apk add --no-cache \
  mtools \
  dosfstools
COPY make-config /
RUN mkdir /conf

WORKDIR /
ENTRYPOINT [ "/make-config" ]
