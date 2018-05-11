FROM linuxkit/alpine:90571a1a9059f3bf33ca3431bc5396aa837a47d3 as build

COPY virt-gicv3.dts /dt/virt-gicv3.dts

WORKDIR /dt
RUN apk add --no-cache dtc
RUN dtc -O dtb -o /dt/virt-gicv3.dtb -I dts /dt/virt-gicv3.dts

RUN [ `uname -m` = aarch64 ] || rm -f /dt/*

FROM scratch
ENTRYPOINT []
CMD []
COPY --from=build /dt /EFI/BOOT
