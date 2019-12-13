FROM linuxkit/memlogd:v0.5 as memlogd
FROM alpine:3.10.3
WORKDIR /
COPY --from=memlogd /usr/bin/logread /usr/bin/logread
COPY init.sh /init.sh

ENTRYPOINT []
CMD ["/init.sh"]
