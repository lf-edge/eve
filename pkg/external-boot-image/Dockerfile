# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

FROM lfedge/eve-xen-tools:18c6ea0119ec42fdc3e8eda57c1bfad6bf44b08f as initrd-build
FROM docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.38-generic-d2da815271a2-gcc as  kernel-build

FROM scratch
COPY --from=initrd-build --chmod=666 /usr/lib/xen/boot/runx-initrd /
COPY --from=kernel-build --chmod=666 /kernel /
