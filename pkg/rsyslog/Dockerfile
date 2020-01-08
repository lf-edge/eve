FROM lfedge/eve-alpine:d743b7f39803ab1b9c8b13e29186c99797d8c4bc as build
RUN apk add --allow-untrusted -X /mirror/3.10 --no-cache -p /mirror/3.10/rootfs \
            rsyslog=8.1904.0-r1 \
            rsyslog-mmjsonparse=8.1904.0-r1

FROM scratch
WORKDIR /
COPY --from=build /mirror/3.10/rootfs /
COPY rsyslog.conf /etc/rsyslog.conf
COPY init.sh /init.sh

ENTRYPOINT []
CMD ["/init.sh"]
