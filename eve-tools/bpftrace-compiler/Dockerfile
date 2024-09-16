FROM alpine:latest

RUN apk update
RUN apk add qemu-system-x86_64 qemu-system-aarch64 go make git docker

COPY init_docker_tests.sh /init_docker_tests.sh
RUN chmod u+x /init_docker_tests.sh

RUN mkdir /src

WORKDIR /src

ENTRYPOINT ["/init_docker_tests.sh"]
