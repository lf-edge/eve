ARG GOVER=1.15.3
FROM golang:${GOVER}-alpine as build
RUN apk add --no-cache   \
        libc-dev=0.7.2-r3\
        git=2.26.2-r0    \
        gcc=9.3.0-r2     \
        linux-headers=5.4.5-r1

COPY ./  /newlog/.
WORKDIR /newlog

RUN GO111MODULE=on CGO_ENABLED=1 go build -mod=vendor -o newlogd ./cmd
RUN strip newlogd

FROM alpine:3.8
COPY --from=build /newlog/newlogd /usr/bin
COPY newlogd-init.sh /newlogd-init.sh

WORKDIR /newlog
ENTRYPOINT []
CMD ["/newlogd-init.sh"]
