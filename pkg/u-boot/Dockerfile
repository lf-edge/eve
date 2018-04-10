#FROM alpine@sha256:286be1c7f84de7cbae6cf8aa4e13b3ce2f2512353b3e734336e47e92de4a881e as build
FROM alpine@sha256:2ed83b97395753366d69f46eb997970baf60fced4cd85932afcfee5ee97d568f as build
#FROM alpine:3.7 as build

ENV VERSION v2018.03 
ENV SOURCE_URL=https://github.com/u-boot/u-boot/archive/${VERSION}.tar.gz

RUN apk add --no-cache \
    binutils-dev \
    build-base \
    bc \
    curl

RUN [ -f `basename ${SOURCE_URL}` ] || curl -fsSL ${SOURCE_URL} | tar -C / -xzvf -
RUN cd /u-boot* ; make vexpress_ca9x4_config ; make

FROM scratch
ENTRYPOINT []
CMD []
WORKDIR /boot
COPY --from=build /u-boot*/u-boot .
