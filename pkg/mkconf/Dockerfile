FROM linuxkit/alpine:90571a1a9059f3bf33ca3431bc5396aa837a47d3
RUN apk add --no-cache \
  mtools=4.0.18-r2     \
  dosfstools=4.1-r1    \
  dtc=1.4.4-r0
COPY make-config /
RUN mkdir /conf

WORKDIR /
ENTRYPOINT [ "/make-config" ]
