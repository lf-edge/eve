# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The container images kube-init needs at first boot (KubeVirt, CDI, Longhorn,
# Multus, kube-vip), as a plain OCI layout. linuxkit unpacks a volume image
# into the rootfs at build time and overlay-mounts it at boot, so the layout
# arrives as files under /images in the kube container.
#
# LAYER_FORMAT=erofs converts each layer here so the device places blobs
# instead of running mkfs.erofs per layer on its single dom0 vCPU.

# Runs natively on the builder: nothing in this stage ships, and it compiles
# erofs-utils and then converts every layer of 28 images. TARGETARCH below,
# not this platform, decides what the payload holds.
FROM --platform=$BUILDPLATFORM lfedge/eve-alpine:ef20bcb617db5545765f4d7486621cf606e5595e AS build

ARG TARGETARCH
ARG LAYER_FORMAT=erofs
# Uncompressed: the payload rides inside the squashfs-xz rootfs, and xz cannot
# compress lz4hc output (1.809 GB of rootfs against 1.481 GB, and two
# decompressions per read instead of one). Set an mkfs.erofs -z<algo> if the
# payload ever ships outside the rootfs.
ARG LAYER_COMPRESSION=none

# Build stage only; PKGS is empty because /out holds nothing but the payload.
ENV BUILD_PKGS="skopeo python3 build-base autoconf automake libtool pkgconf git \
        lz4-dev zlib-dev xz-dev util-linux-dev"
RUN eve-alpine-deploy.sh

# The mirror's erofs-utils 1.8.6 mangles usr-merge base layers (files under a
# symlinked dir like lib64 -> usr/lib64) into a bogus ~2TiB image, so build
# 1.9.2 + the symlink fix, as pkg/kube does for the device. Pinned by commit:
# a re-pointed tag would change the binary under an unchanged package hash.
ADD https://github.com/erofs/erofs-utils.git#05b56bd5acee1f0ee5ee79e47e3503700225b9a1 /erofs-src
COPY 0001-erofs-utils-lib-follow-symlinks-on-intermediate-tar-.patch /erofs-src/
WORKDIR /erofs-src
RUN git apply 0001-erofs-utils-lib-follow-symlinks-on-intermediate-tar-.patch && \
    ./autogen.sh && ./configure --enable-lz4 && make -j"$(nproc)" && \
    install -D -m0755 mkfs/mkfs.erofs /usr/local/sbin/mkfs.erofs && \
    mkfs.erofs --version

# busybox sh has no pipefail, and the payload RUN pipes.
SHELL ["/bin/ash", "-o", "pipefail", "-c"]

WORKDIR /w
COPY upstream-images.list /w/upstream-images.list
COPY oci-rewrite-layers.py /w/oci-rewrite-layers.py

# Copy every ref into one layout (skopeo dedups by digest within it, and
# cannot sync into a layout, hence a copy per ref), convert the layers, ship
# the result. /oci-cache persists across builds, so bumping one image re-pulls
# only that image.
RUN --mount=type=cache,target=/oci-cache,id=kube-images-$TARGETARCH \
    set -eu; \
    mkdir -p /oci-cache/oci-layout /out; \
    while read -r line; do \
        [ -n "$line" ] || continue; \
        case "$line" in \#*) continue ;; esac; \
        # Lines are repo:tag@sha256:...; containers/image refuses a reference
        # carrying both, so pull by digest (which verifies it) and name the
        # entry by tag, which is what kubelet's pod specs reference.
        # --override-arch is what makes the native cross-build ship the
        # target's images rather than the builder's.
        ref="${line%@*}"; \
        digest="${line#*@}"; \
        dest=$(printf '%s' "$ref" | tr '/:' '__'); \
        echo "[skopeo] $ref ($digest) -> $TARGETARCH"; \
        skopeo copy --preserve-digests \
            --override-os linux --override-arch "$TARGETARCH" \
            "docker://${ref%:*}@$digest" \
            "oci:/oci-cache/oci-layout:$dest"; \
    done < /w/upstream-images.list; \
    # kube-init maps these sanitised ref names back to registry refs.
    cp /w/upstream-images.list /oci-cache/oci-layout/upstream-images.list; \
    echo "[rewrite] layers -> $LAYER_FORMAT"; \
    # Keep the cache's source tars: skopeo reuses a blob only if it is still
    # in the destination, so pruning here would re-pull all 28 next build.
    python3 /w/oci-rewrite-layers.py /oci-cache/oci-layout --format "$LAYER_FORMAT" \
        --compression "$LAYER_COMPRESSION" --keep-unreachable; \
    # A ref that failed to copy, or one dropped from the list but still in the
    # cache, would otherwise ship unnoticed.
    want=$(grep -c '^[^#]' /w/upstream-images.list); \
    got=$(python3 -c "import json;print(sum(1 for m in json.load(open('/oci-cache/oci-layout/index.json'))['manifests'] if m.get('annotations',{}).get('org.opencontainers.image.ref.name')))"); \
    [ "$want" = "$got" ] || { echo "payload has $got named images, list has $want"; exit 1; }; \
    cp -a /oci-cache/oci-layout/. /out/; \
    python3 /w/oci-rewrite-layers.py /out --prune-only

FROM scratch
COPY --from=build /out/ /
