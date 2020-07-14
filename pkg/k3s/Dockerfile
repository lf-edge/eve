ARG GOVER=1.14.4
FROM golang:${GOVER}-alpine as build
ARG K3SVER=v1.18.4+k3s1
RUN apk add --no-cache --initdb \
        make=4.3-r0 \
        gcc=9.3.0-r2 \
        musl-dev=1.1.24-r9 \
        git=2.26.2-r0 \
        linux-headers=5.4.5-r1 \
        curl=7.69.1-r0 \
        bash=5.0.17-r0 \
        pkgconf=1.7.2-r0 \
        libseccomp-dev=2.4.3-r0

WORKDIR /k3s
RUN git clone -b ${K3SVER} --depth 1 https://github.com/rancher/k3s.git .
RUN scripts/download
RUN scripts/build
RUN scripts/package-cli

WORKDIR /out
RUN mv /k3s/bin/containerd /k3s/bin/containerd-shim /k3s/bin/containerd-shim-runc-v2 /k3s/bin/ctr .

FROM scratch
COPY --from=build /out /usr/bin
COPY rootfs/ /
