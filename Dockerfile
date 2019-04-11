# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.9.1-alpine AS build
RUN apk update
RUN apk add --no-cache git gcc linux-headers libc-dev util-linux

# These three are supporting rudimentary cross-build capabilities.
# The only one supported so far is cross compiling for aarch64 on x86
ENV CGO_ENABLED=1
ARG GOARCH=
ARG CROSS_GCC=https://musl.cc/aarch64-linux-musleabi-cross.tgz
RUN [ -z "$GOARCH" ] || (cd / ; apk add --no-cache wget && wget -O - $CROSS_GCC | tar xzvf -)

ADD ./  /go/src/github.com/zededa/go-provision/
ADD conf/root-certificate.pem conf/server conf/server.production /config/
ADD scripts/device-steps.sh \
    scripts/find-uplink.sh \
    scripts/generate-device.sh \
    scripts/generate-self-signed.sh \
    scripts/handlezedserverconfig.sh \
    scripts/watchdog-report.sh \
  /opt/zededa/bin/
ADD examples /opt/zededa/examples
ADD conf/AssignableAdapters /var/tmp/zededa/AssignableAdapters
ADD conf/DeviceNetworkConfig /var/tmp/zededa/DeviceNetworkConfig
ADD conf/lisp.config.base /var/tmp/zededa/lisp.config.base

# XXX temporary until we have a version for all of baseOS/rootfs
RUN (cd ./src/github.com/zededa/go-provision/; scripts/getversion.sh >/opt/zededa/bin/versioninfo)
RUN cp /opt/zededa/bin/versioninfo /opt/zededa/bin/versioninfo.1
# Echo for builders enjoyment
RUN echo Building: `cat /opt/zededa/bin/versioninfo`

# go install and go vet
RUN [ -z "$GOARCH" ] || export CC=$(echo /*-cross/bin/*-gcc)           ;\
    go install github.com/zededa/go-provision/zedbox/... && \
    echo "Running go vet" && go vet ./... && \
    if [ -f /go/bin/*/zedbox ] ; then mv /go/bin/*/zedbox /go/bin ; fi

RUN ln -s /go/bin/zedbox /opt/zededa/bin/zedbox ;\
    for app in   \
      client domainmgr downloader hardwaremodel identitymgr ledmanager \
      logmanager verifier zedagent zedmanager zedrouter ipcmonitor nim \
      waitforaddr diag baseosmgr wstunnelclient conntrack;\
    do ln -s zedbox /opt/zededa/bin/$app ; done

# Second stage of the build is creating a minimalistic container
FROM scratch
COPY --from=build /opt/zededa/bin /opt/zededa/bin
COPY --from=build /opt/zededa/examples /opt/zededa/examples
COPY --from=build /var/tmp/zededa/AssignableAdapters /var/tmp/zededa/AssignableAdapters
COPY --from=build /var/tmp/zededa/DeviceNetworkConfig /var/tmp/zededa/DeviceNetworkConfig
COPY --from=build /var/tmp/zededa/lisp.config.base /var/tmp/zededa/lisp.config.base

# We have to make sure configs survive in some location, but they don't pollute
# the default /config (since that is expected to be an empty mount point)
COPY --from=build /config /opt/zededa/examples/config
COPY --from=build /go/bin/* /opt/zededa/bin/
WORKDIR /opt/zededa/bin
CMD /bin/ash
