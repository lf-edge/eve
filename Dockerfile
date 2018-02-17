FROM golang:1.9.1-alpine AS build
RUN apk update
ARG PF_RING_VERSION=6.6.0-stable
RUN apk add --no-cache bison flex git gcc linux-headers libc-dev make util-linux

ADD ./  /go/src/github.com/zededa/go-provision/
ADD ./cmd/dataplane/itr  /go/src/github.com/zededa/go-provision/dataplane/itr
ADD ./cmd/dataplane/etr  /go/src/github.com/zededa/go-provision/dataplane/etr
ADD ./cmd/dataplane/fib  /go/src/github.com/zededa/go-provision/dataplane/fib
ADD etc /opt/zededa/etc
ADD README /opt/zededa/etc
ADD etc /config
ADD scripts/device-steps.sh \
    scripts/find-uplink.sh \
    scripts/generate-device.sh \
    scripts/generate-onboard.sh \
    scripts/generate-self-signed.sh \
    scripts/run-ocsp.sh \
    scripts/zupgrade.sh \
  /opt/zededa/bin/
ADD examples /opt/zededa/examples
ADD AssignableAdapters /var/tmp/zededa/AssignableAdapters
ADD DeviceNetworkConfig /var/tmp/zededa/DeviceNetworkConfig

RUN mkdir -p /tmp/github; cd /tmp/github; git clone -b ${PF_RING_VERSION} https://github.com/ntop/PF_RING.git; cd PF_RING/userland; make install; cp ../kernel/linux/pf_ring.h /usr/include/linux

RUN go get github.com/zededa/go-provision/cmd/...
# this is taking care of on-boarding code that has to interact with LISP
RUN go get github.com/zededa/go-provision/oldcmd/...
RUN cd /opt/zededa/bin ; ln -s /go/bin/* .

RUN ash -c 'ID=`uuidgen | tr "[A-Z]" "[a-z]"` ; cat /tmp/gg.json | sed -e s"#1a0d85d9-5e83-4589-b56f-cedabc9a8c0d#${ID}#" > /config/${ID}.json'

# Now building LISP
FROM zededa/lisp:latest AS lisp

# Second stage of the build is creating a minimalistic container
FROM scratch
COPY --from=build /opt/zededa/bin /opt/zededa/bin
COPY --from=build /opt/zededa/examples /opt/zededa/examples
COPY --from=build /var/tmp/zededa/AssignableAdapters /var/tmp/zededa/AssignableAdapters
COPY --from=build /var/tmp/zededa/DeviceNetworkConfig /var/tmp/zededa/DeviceNetworkConfig
COPY --from=build /config /config
COPY --from=build /go/bin/* /opt/zededa/bin/
COPY --from=build /usr/local/lib/* /usr/local/lib/
COPY --from=build /usr/local/include/* /opt/zededa/include/
COPY --from=build /usr/include/linux/pf_ring.h /opt/zededa/include/linux/
COPY --from=lisp /lisp /opt/zededa/lisp/
COPY --from=lisp /usr/bin/pydoc /usr/bin/smtpd.py /usr/bin/python* /usr/bin/
COPY --from=lisp /usr/lib/libpython* /usr/lib/libffi.so* /usr/lib/
COPY --from=lisp /usr/lib/python2.7 /usr/lib/python2.7/
WORKDIR /opt/zededa/bin
CMD /bin/ash
