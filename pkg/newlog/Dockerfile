ARG GOVER=1.12.4
FROM golang:${GOVER}-alpine as build
RUN apk add --no-cache   \
        git=2.20.4-r0    \
        gcc=8.3.0-r0     \
        linux-headers=4.18.13-r1

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
