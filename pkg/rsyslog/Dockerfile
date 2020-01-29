FROM alpine:3.10.3
WORKDIR /
RUN apk add --no-cache \
            rsyslog=8.1904.0-r1 \
            rsyslog-mmjsonparse=8.1904.0-r1
COPY rsyslog.conf /etc/rsyslog.conf
COPY init.sh /init.sh
COPY rotate.sh /rotate.sh
COPY start-rsyslogd.sh /start-rsyslogd.sh
COPY monitor-rsyslog.sh /monitor-rsyslog.sh

ENTRYPOINT []
CMD ["/init.sh"]
