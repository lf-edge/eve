FROM alpine:3.9

WORKDIR /bits

RUN apk add --no-cache qemu-system-x86_64 qemu-system-aarch64 bash make git squashfs-tools
COPY . /bits/
COPY runme.sh /
RUN ln -s installer/* .

ENTRYPOINT [ "/runme.sh" ]
