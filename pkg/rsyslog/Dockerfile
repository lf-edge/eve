FROM linuxkit/alpine:3683c9a66cd4da40bd7d6c7da599b2dcd738b559 AS build

RUN apk add --no-cache  \
    go=1.10.1-r0        \
    musl-dev=1.1.19-r10 \
    binutils=2.30-r5

COPY cmd/waitforsyslog /go/src/waitforsyslog
RUN go-compile.sh /go/src/waitforsyslog
RUN strip /go/bin/waitforsyslog

FROM alpine:3.10.3
WORKDIR /
RUN apk add --no-cache \
            rsyslog=8.1904.0-r1 \
            rsyslog-mmjsonparse=8.1904.0-r1
COPY rsyslog.conf /etc/rsyslog.conf
COPY init.sh /init.sh
COPY --from=build /go/bin/waitforsyslog /bin/

ENTRYPOINT []
CMD ["/init.sh"]
