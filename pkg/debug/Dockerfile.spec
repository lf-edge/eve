FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544

ENV BUILD_PKGS="jq pciutils usbutils util-linux"

RUN eve-ubuntu-deploy.sh

WORKDIR /usr/bin
COPY spec.sh .

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

RUN echo "Testing spec.sh -v..." && \
    ./spec.sh -v | tee /dev/stderr | jq . > /dev/null

RUN echo "Testing spec.sh..." && \
    ./spec.sh | tee /dev/stderr | jq . > /dev/null

CMD ["./spec.sh", "-v"]
