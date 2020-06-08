FROM linuxkit/alpine:90571a1a9059f3bf33ca3431bc5396aa837a47d3 as build

RUN mkdir -p /out/etc/apk /out/boot && cp -r /etc/apk/* /out/etc/apk/
RUN apk add --no-cache --initdb -p /out \
  busybox=1.27.2-r8    \
  mtools=4.0.18-r2     \
  dosfstools=4.1-r1
COPY make-config /out/
RUN mkdir -p /out/conf/raw

FROM scratch
COPY --from=build /out /

WORKDIR /
ENTRYPOINT [ "/make-config" ]
