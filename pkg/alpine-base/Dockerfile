FROM alpine:3.22 AS builder

WORKDIR /rootfs

# Fetch the required miniroot archive
RUN case $(uname -m) in \
    x86_64|aarch64|riscv64) \
        ROOTFS_URL="https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/$(uname -m)/alpine-minirootfs-3.22.2-$(uname -m).tar.gz"; \
        ;; \
    *) echo "Unsupported architecture $(uname -m). Exiting" && exit 1 \
      ;; \
    esac && \
    wget -q -O /tmp/rootfs.tar.gz "$ROOTFS_URL" && \
    tar xzf /tmp/rootfs.tar.gz

FROM scratch

# seed the root filesystem
COPY --from=builder /rootfs/ /

# set the defaults for docker run
ENV PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CMD ["/bin/sh"]
