FROM lfedge/eve-alpine:99db0c3af59a9656315c9d7a0ad8a24f631134b0 AS build
ENV BUILD_PKGS go gcc musl-dev linux-headers
RUN eve-alpine-deploy.sh

ENV GOPATH=/go PATH=$PATH:/go/bin

# see https://github.com/golang/go/issues/23672
ENV CGO_CFLAGS_ALLOW=(-mrdrnd|-mrdseed)

COPY cmd/rngd/ /go/src/rngd/
RUN REQUIRE_CGO=1 go-compile.sh /go/src/rngd

FROM scratch
ENTRYPOINT []
WORKDIR /
COPY --from=build /go/bin/rngd /sbin/rngd
CMD ["/sbin/rngd"]
