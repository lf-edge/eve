ARG GOVER=1.12.4
FROM golang:${GOVER}-alpine as build
RUN apk add --no-cache           \
        git gcc=8.3.0-r0         \
        linux-headers=4.18.13-r1

ENV GOFLAGS=-mod=vendor
ENV GO111MODULE=on
ENV CGO_ENABLED=1

COPY ./  /newlog/.
WORKDIR /newlog

RUN go build -mod=vendor -o newlogd ./cmd

FROM alpine:3.8
COPY --from=build /newlog/newlogd /usr/bin
COPY newlogd-init.sh /newlogd-init.sh

WORKDIR /newlog
ENTRYPOINT []
CMD ["/newlogd-init.sh"]

