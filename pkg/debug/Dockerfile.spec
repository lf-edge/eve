FROM lfedge/eve-alpine:80c5dbe1085d0650030be8a110eaec66ef532672

ENV BUILD_PKGS="jq pciutils usbutils lsblk"

RUN eve-alpine-deploy.sh

WORKDIR /usr/bin
COPY spec.sh .

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

RUN echo "Testing spec.sh -v..." && \
    ./spec.sh -v | tee /dev/stderr | jq . > /dev/null

RUN echo "Testing spec.sh..." && \
    ./spec.sh | tee /dev/stderr | jq . > /dev/null

CMD ["./spec.sh", "-v"]