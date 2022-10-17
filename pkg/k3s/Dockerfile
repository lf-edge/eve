FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 as build
ENV BUILD_PKGS make gcc git musl-dev linux-headers curl bash pkgconf libseccomp-dev go patch
RUN eve-alpine-deploy.sh

ARG K3SVER=v1.18.4+k3s1

WORKDIR /k3s
COPY 0001-go-mod.patch /tmp/
RUN git clone -b ${K3SVER} --depth 1 https://github.com/rancher/k3s.git . &&\
    echo "git https://github.com/rancher/k3s.git ${K3SVER}" >>/source-info
RUN patch -p1 < /tmp/0001-go-mod.patch
RUN scripts/download
RUN scripts/build
RUN scripts/package-cli

WORKDIR /out
RUN mv /k3s/bin/containerd /k3s/bin/containerd-shim /k3s/bin/containerd-shim-runc-v2 /k3s/bin/ctr .

FROM scratch
COPY --from=build /out /usr/bin
COPY --from=build /source-info /
COPY rootfs/ /
