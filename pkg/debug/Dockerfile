FROM alpine:3.12
ENTRYPOINT []
WORKDIR /

RUN apk add --no-cache pciutils usbutils vim tcpdump gdb valgrind perf util-linux

COPY debug-spin.sh /

CMD ["/debug-spin.sh"]
