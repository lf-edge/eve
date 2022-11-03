FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 as build
ENV BUILD_PKGS git go
ENV PKGS alpine-baselayout musl-utils
RUN eve-alpine-deploy.sh

COPY src/  /measure-config/.
COPY go.mod /measure-config/.
COPY go.sum /measure-config/.
WORKDIR /measure-config

ENV CGO_ENABLED=0
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# hadolint ignore=SC2046
RUN echo "Running go vet" && go vet ./... && echo "Running go fmt" && \
    ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
    if [ -n "$ERR" ] ; then echo "go fmt Failed - ERR: $ERR"; exit 1 ; fi

RUN go build -ldflags "-s -w" -o /out/usr/bin/measure-config .

FROM scratch
COPY --from=build /out/ /

ENV PATH="/run/debug/usr/bin:${PATH}"

WORKDIR /
ENTRYPOINT ["/usr/bin/measure-config"]
CMD []