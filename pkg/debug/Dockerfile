FROM alpine:3.8
ENTRYPOINT []
WORKDIR /

RUN apk add --no-cache pciutils usbutils vim tcpdump

COPY debug-spin.sh /

CMD ["/debug-spin.sh"]
