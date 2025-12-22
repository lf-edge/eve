FROM lfedge/eve-alpine:745ae9066273c73b0fd879c4ba4ff626a8392d04

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