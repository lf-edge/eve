FROM alpine:3.8 as build

WORKDIR /
RUN apk add --no-cache \
    linux-firmware-other \
    linux-firmware-ath10k \
    linux-firmware-mrvl

FROM scratch
ENTRYPOINT []
WORKDIR /
COPY --from=build /lib/firmware/ath10k /lib/firmware/ath10k
COPY --from=build /lib/firmware/mrvl /lib/firmware/mrvl
COPY --from=build /lib/firmware/rt2870.bin /lib/firmware/rt2870.bin
