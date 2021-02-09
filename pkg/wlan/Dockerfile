FROM alpine:3.13.1 as build

WORKDIR /

RUN apk add --no-cache \
    wireless-tools \
    wpa_supplicant 

COPY init.sh /init.sh

ENTRYPOINT []
CMD ["/init.sh"]
