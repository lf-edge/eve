FROM lfedge/eve-ubuntu:ce501daedafe54c66d1d2561e0cd215d49ea1f60

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
