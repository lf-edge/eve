# hadolint ignore=DL3006
FROM lfedge/eve-gpt-tools:19ef56f5014fab1978a6e98b047d4498eabf8295-amd64 as gpttools

From alpine:3.8
WORKDIR /
COPY rsyslog@lists.adiscon.com-5a55e598.rsa.pub /etc/apk/keys/rsyslog@lists.adiscon.com-5a55e598.rsa.pub
# hadolint ignore=DL3018
RUN echo "http://alpine.rsyslog.com/3.7/stable" >> /etc/apk/repositories \
            && apk --no-cache update \
            && apk add --no-cache \
            rsyslog \
            rsyslog-imptcp \
            rsyslog-mmjsonparse \
            rsyslog-omstdout
COPY rsyslog.conf /etc/rsyslog.conf
COPY init.sh /init.sh
COPY --from=gpttools / /

ENTRYPOINT []
CMD ["/init.sh"]
