FROM linuxkit/alpine:90571a1a9059f3bf33ca3431bc5396aa837a47d3 as build

COPY *.dts /dt/

WORKDIR /dt
RUN apk add --no-cache dtc
RUN for i in *dts ; do dtc -O dtb -o ${i%%.dts}.dtb -I dts $i ; done

RUN [ `uname -m` = aarch64 ] || rm -f /dt/*

FROM scratch
ENTRYPOINT []
CMD []
COPY --from=build /dt /EFI/BOOT
