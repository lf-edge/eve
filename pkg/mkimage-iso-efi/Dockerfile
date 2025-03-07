# to have access to packages for alternate arches
# hadolint ignore=DL3029
FROM --platform=linux/amd64 lfedge/eve-alpine:591df01e581889c3027514c8a91feaca1c8ad49f AS build-amd64
# hadolint ignore=DL3029
FROM --platform=linux/arm64 lfedge/eve-alpine:591df01e581889c3027514c8a91feaca1c8ad49f AS build-arm64

# the one we build is our local
FROM lfedge/eve-alpine:591df01e581889c3027514c8a91feaca1c8ad49f AS build

ENV PKGS dosfstools libarchive-tools binutils mtools xorriso mkinitfs squashfs-tools
RUN eve-alpine-deploy.sh

RUN echo "mtools_skip_check=1" >> /out/etc/mtools.conf

# from https://git.alpinelinux.org/aports/tree/main/mkinitfs/mkinitfs.post-install?id=7b64ec6e904040bd75ea21529b4fce61c908a553
# we need to simulate mkinitfs.post-install from the original APK file
# --- Quote ---
# safety. if nlplug-findfs is missing in the initramfs image we may end up
# with an unbootable system.
RUN if ! grep -q -w /sbin/nlplug-findfs  /out/etc/mkinitfs/features.d/base.files; then \
        echo "/sbin/nlplug-findfs" >> /out/etc/mkinitfs/features.d/base.files; \
    fi
RUN echo /bin/grep >> /out/etc/mkinitfs/features.d/base.files

# for alternate architectures
COPY --from=build-amd64 /bin/busybox /out/arch/amd64/bin/
COPY --from=build-amd64 /lib/ld-musl* /out/arch/amd64/lib/
COPY --from=build-arm64 /bin/busybox /out/arch/arm64/bin/
COPY --from=build-arm64 /lib/ld-musl* /out/arch/arm64/lib/

FROM scratch
COPY --from=build /out /
COPY . /
WORKDIR /
ENTRYPOINT [ "/make-efi" ]
