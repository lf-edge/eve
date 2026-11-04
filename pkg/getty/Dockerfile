# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# linuxkit's getty image rebuilt on eve-alpine: the same Alpine packages
# (less wireguard-tools, which nothing in EVE uses) and linuxkit's own
# scripts under etc/ and usr/, so that the console login layer follows
# eve-alpine's package refreshes instead of linuxkit's package releases.
# pillar relies on /etc/init.d/001-getty being present in the rootfs.

FROM lfedge/eve-alpine:8c9af5568049068f10bc630065793c15d52fa931 AS mirror
ENV PKGS="alpine-baselayout apk-tools busybox ca-certificates musl tini util-linux"
RUN eve-alpine-deploy.sh

# rungetty.sh needs a setsid(1) that supports -w; once the init layers are
# combined, /usr/bin/setsid may come from another image, so keep a copy
# under a name of its own, as linuxkit does.
RUN cp /out/usr/bin/setsid /out/usr/bin/setsid.getty
# no rogue inittab in the rootfs
RUN rm -rf /out/etc/inittab

FROM scratch
ENTRYPOINT ["/sbin/tini","-s","-v","--"]
WORKDIR /
COPY --from=mirror /out/ /
COPY usr/ /usr/
COPY etc/ /etc/
CMD ["/usr/bin/rungetty.sh"]
