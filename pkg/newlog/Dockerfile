FROM lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb as build
ENV BUILD_PKGS git go
ENV PKGS coreutils
RUN eve-alpine-deploy.sh

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
