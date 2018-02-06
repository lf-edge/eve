FROM golang:1.9.1-alpine AS build
RUN apk add --no-cache git gcc linux-headers libc-dev util-linux

ADD ./  /go/src/github.com/zededa/go-provision/
ADD etc /config
ADD scripts/device-steps.sh \
    scripts/find-uplink.sh \
    scripts/generate-device.sh \
    scripts/generate-onboard.sh \
    scripts/generate-self-signed.sh \
    scripts/run-ocsp.sh \
    scripts/zupgrade.sh \
  /opt/zededa/bin/
ADD examples/x86-ggc-1a0d85d9-5e83-4589-b56f-cedabc9a8c0d.json /tmp/gg.json

RUN go get github.com/zededa/go-provision/cmd/...
# this is taking care of on-boarding code that has to interact with LISP
RUN go get github.com/zededa/go-provision/oldcmd/...
RUN cd /opt/zededa/bin ; ln -s /go/bin/* .

RUN ash -c 'ID=`uuidgen | tr "[A-Z]" "[a-z]"` ; cat /tmp/gg.json | sed -e s"#1a0d85d9-5e83-4589-b56f-cedabc9a8c0d#${ID}#" > /config/${ID}.json'

# Now building LISP
FROM zededa/lisp:latest AS lisp

# Second stage of the build is creating a minimalistic container
FROM scratch
COPY --from=build /opt/zededa /opt/zededa
COPY --from=build /go/bin/* /opt/zededa/bin/
COPY --from=lisp /lisp /opt/zededa/lisp/
COPY --from=lisp /usr/bin/pydoc /usr/bin/smtpd.py /usr/bin/python* /usr/bin/
COPY --from=lisp /usr/lib/libpython* /usr/lib/libffi.so* /usr/lib/
COPY --from=lisp /usr/lib/python2.7 /usr/lib/python2.7/
WORKDIR /opt/zededa/bin
CMD /bin/ash
