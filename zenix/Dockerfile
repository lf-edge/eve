FROM alpine:edge

RUN apk add --no-cache qemu-system-x86_64 qemu-system-aarch64 bash make git
COPY Makefile installer.iso fallback.img rootfs.img config.img /bits/
COPY OVMF.fd /bits/bios/OVMF.fd
COPY runme.sh /

WORKDIR /bits
ENTRYPOINT [ "/runme.sh" ]
