# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

FROM lfedge/eve-xen-tools:2d7a0514d93d609246fc6a54df8405d7a978fdc4 as initrd-build
FROM lfedge/eve-kernel:79e9c87350a9d7255a94834a3cf3f9c8ea0348bd as kernel-build

FROM scratch
COPY --from=initrd-build --chmod=666 /usr/lib/xen/boot/runx-initrd /
COPY --from=kernel-build --chmod=666 /kernel /
