FROM alpine:3.10.3
WORKDIR /
# hadolint ignore=DL3018
RUN apk add --no-cache bash glib squashfs-tools util-linux e2fsprogs \
        e2fsprogs-extra keyutils
COPY storage-init.sh /storage-init.sh

ENTRYPOINT []
CMD ["/storage-init.sh"]
