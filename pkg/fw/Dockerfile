FROM alpine:3.8 as build

WORKDIR /
RUN apk add --no-cache \
    linux-firmware-other \
    linux-firmware-ath10k \
    linux-firmware-mrvl \
    linux-firmware-rtlwifi \
    linux-firmware-other

FROM scratch
ENTRYPOINT []
WORKDIR /
# FIXME: we're currently using ath10k firmware supplied
# by Advantech. This is getting upstreamed and when it
# does we should switch back to linux-firmware-ath10k from Alpine
# COPY --from=build /lib/firmware/ath10k /lib/firmware/ath10k
COPY ath10k /lib/firmware/ath10k
# FIXME: this is binary block firmware for HiKey
COPY ti-connectivity /lib/firmware/ti-connectivity
COPY --from=build /lib/firmware/mrvl /lib/firmware/mrvl
COPY --from=build /lib/firmware/rt2870.bin /lib/firmware/rt2870.bin
COPY --from=build /lib/firmware/rtlwifi /lib/firmware/rtlwifi
COPY --from=build /lib/firmware/iwlwifi-8265* /lib/firmware/
