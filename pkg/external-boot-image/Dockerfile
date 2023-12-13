# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

ARG KERNEL=latest
ARG XENTOOLS=latest

FROM lfedge/eve-xen-tools:$XENTOOLS as initrd-build
FROM lfedge/eve-kernel:$KERNEL as kernel-build

FROM scratch
COPY --from=initrd-build --chmod=666 /usr/lib/xen/boot/runx-initrd /
COPY --from=kernel-build --chmod=666 /kernel /
