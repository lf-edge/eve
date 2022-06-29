FROM lfedge/eve-alpine:6.7.0 as build
ENV BUILD_PKGS git go
ENV PKGS alpine-baselayout musl-utils iproute2 iptables
RUN eve-alpine-deploy.sh

# FIXME bump eve-alpine to alpine 3.14
# hadolint ignore=DL3018
RUN apk --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/v3.14/community add -U --upgrade go && go version

COPY src/  /edge-view/.
COPY go.mod /edge-view/.
COPY go.sum /edge-view/.
WORKDIR /edge-view

ENV CGO_ENABLED=0
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# hadolint ignore=SC2046
RUN echo "Running go vet" && go vet ./... && echo "Running go fmt" && \
    ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
    if [ -n "$ERR" ] ; then echo "go fmt Failed - ERR: $ERR"; exit 1 ; fi

RUN go build -ldflags "-s -w" -o /out/usr/bin/edge-view . && cp edge-view-init.sh /out/usr/bin

FROM scratch
COPY --from=build /out/ /
RUN mkdir -p /tmp

ENV PATH="/run/debug/usr/bin:${PATH}"

WORKDIR /
ENTRYPOINT ["/usr/bin/edge-view-init.sh"]
CMD []
