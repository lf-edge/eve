From alpine:3.8
WORKDIR /
COPY rsyslog@lists.adiscon.com-5a55e598.rsa.pub /etc/apk/keys/rsyslog@lists.adiscon.com-5a55e598.rsa.pub
RUN echo "http://alpine.rsyslog.com/3.7/stable" >> /etc/apk/repositories \
			&& apk --no-cache update \
			&& apk add --no-cache \
			rsyslog \
			rsyslog-imptcp \
			rsyslog-mmjsonparse \
			rsyslog-omstdout
COPY rsyslog.conf /etc/rsyslog.conf
COPY init.sh /init.sh

ENTRYPOINT []
CMD ["/init.sh"]
