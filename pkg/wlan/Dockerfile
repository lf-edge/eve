FROM alpine:3.6 as build

RUN mkdir -p /out/etc/apk && cp -r /etc/apk/* /out/etc/apk/
# Can you believe I need to do the following? One word: dbus
RUN mkdir /out/dev ; mknod /out/dev/urandom c 1 9
RUN apk add --no-cache --initdb -p /out \
    linux-firmware \
    wireless-tools \
    wpa_supplicant 
RUN mv /out/lib/firmware/rt2870.bin / ; rm -rf /out/lib/firmware

FROM scratch
ENTRYPOINT []
WORKDIR /
COPY --from=build /out/ /
COPY --from=build /rt2870.bin /lib/firmware/rt2870.bin
COPY etc/ /etc/
COPY usr/ /usr/
CMD ["/usr/bin/wlan-init.sh"]
