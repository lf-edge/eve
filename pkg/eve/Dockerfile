FROM alpine:3.9

RUN apk add --no-cache qemu-system-x86_64 qemu-system-aarch64 bash make git
COPY . /bits/
COPY runme.sh /
RUN touch /bits/bios/OVMF.fd

WORKDIR /bits
ENTRYPOINT [ "/runme.sh" ]
