# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

FROM lfedge/eve-xen-tools:c851ee132e313e380c8d716b21d2c2bc666a329e as initrd-build
FROM docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.38-generic-d2da815271a2-gcc as  kernel-build

FROM scratch
COPY --from=initrd-build --chmod=666 /usr/lib/xen/boot/runx-initrd /
COPY --from=kernel-build --chmod=666 /kernel /
