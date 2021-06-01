FROM lfedge/eve-alpine:6.7.0 as build
ENV BUILD_PKGS libc-dev git gcc linux-headers go
ENV PKGS alpine-baselayout musl-utils
RUN eve-alpine-deploy.sh

COPY ./  /newlog/.
WORKDIR /newlog

RUN GO111MODULE=on CGO_ENABLED=1 go build -mod=vendor -o newlogd ./cmd
RUN strip newlogd
RUN cp newlogd /out/usr/bin

FROM scratch
COPY --from=build /out/ /
COPY newlogd-init.sh /newlogd-init.sh

WORKDIR /newlog
ENTRYPOINT []
CMD ["/newlogd-init.sh"]
