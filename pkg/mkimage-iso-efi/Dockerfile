FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 AS build

ENV PKGS="dosfstools libarchive-tools binutils mtools xorriso mkinitfs squashfs-tools"
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

FROM scratch
COPY --from=build /out /
COPY . /
WORKDIR /
ENTRYPOINT [ "/make-efi" ]
