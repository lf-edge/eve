FROM lfedge/eve-alpine:6.7.0 as build
ENV BUILD_PKGS git go
ENV PKGS busybox
RUN eve-alpine-deploy.sh

# FIXME bump eve-alpine to alpine 3.14
# hadolint ignore=DL3018
RUN apk --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/v3.14/community add -U --upgrade go && go version

COPY ./  /newlog/.
WORKDIR /newlog

RUN GO111MODULE=on CGO_ENABLED=0 go build -ldflags "-s -w" -mod=vendor -o /out/usr/bin/newlogd ./cmd

# required for pubsub
RUN rm -rf /out/var/run && mkdir -p /out/run /out/var && ln -s /run /out/var

FROM scratch
COPY --from=build /out/ /
COPY newlogd-init.sh /newlogd-init.sh

WORKDIR /newlog
ENTRYPOINT []
CMD ["/newlogd-init.sh"]
