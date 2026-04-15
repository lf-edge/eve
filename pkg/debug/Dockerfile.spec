FROM lfedge/eve-alpine:47d267f35e4832f639bf65bbe8a2e7b2f31e3e36

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