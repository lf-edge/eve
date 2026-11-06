FROM lfedge/eve-alpine:a5885b38222df4ba5add4acca2d219c85741bf79

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