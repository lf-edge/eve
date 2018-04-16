FROM golang:1.9.1-alpine AS build
RUN apk update
RUN apk add --no-cache git gcc linux-headers libc-dev util-linux

ADD ./  /go/src/github.com/zededa/go-provision/
ADD etc /config
ADD scripts/device-steps.sh \
    scripts/find-uplink.sh \
    scripts/generate-device.sh \
    scripts/generate-self-signed.sh \
    scripts/handlezedserverconfig.sh \
  /opt/zededa/bin/
ADD examples /opt/zededa/examples
ADD AssignableAdapters /var/tmp/zededa/AssignableAdapters
ADD DeviceNetworkConfig /var/tmp/zededa/DeviceNetworkConfig
ADD lisp.config.base /var/tmp/zededa/lisp.config.base

# XXX temporary until we have a version for all of baseOS/rootfs
RUN (cd ./src/github.com/zededa/go-provision/; scripts/getversion.sh >/opt/zededa/bin/versioninfo)
# Echo for builders enjoyment
RUN echo Building: `cat /opt/zededa/bin/versioninfo`

RUN go install github.com/zededa/go-provision/cmd/...
# this is taking care of on-boarding code that has to interact with LISP
RUN go install github.com/zededa/go-provision/oldcmd/...
RUN cd /opt/zededa/bin ; ln -s /go/bin/* .

# Now building LISP
FROM zededa/lisp:latest AS lisp

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
COPY --from=lisp /lisp/dataplane /opt/zededa/bin/
COPY --from=lisp /lisp /opt/zededa/lisp/
COPY --from=lisp /usr/bin/pydoc /usr/bin/smtpd.py /usr/bin/python* /usr/bin/
COPY --from=lisp /usr/lib/libpython* /usr/lib/libffi.so* /usr/lib/
COPY --from=lisp /usr/lib/python2.7 /usr/lib/python2.7/
COPY --from=lisp /lib /lib
WORKDIR /opt/zededa/bin
CMD /bin/ash
