FROM golang:1.9.1-alpine AS build
RUN apk add --no-cache git gcc linux-headers libc-dev

ADD src /go/src
ADD etc /opt/zededa/etc
ADD README /opt/zededa/etc
ADD scripts/device-steps.sh \
    scripts/find-uplink.sh \
    scripts/generate-device.sh \
    scripts/generate-onboard.sh \
    scripts/generate-self-signed.sh \
    scripts/run-ocsp.sh \
    scripts/zupgrade.sh \
  /opt/zededa/bin/

RUN go get \
  github.com/zededa/go-provision/downloader \
  github.com/zededa/go-provision/verifier \
  github.com/zededa/go-provision/client \
  github.com/zededa/go-provision/server \
  github.com/zededa/go-provision/register \
  github.com/zededa/go-provision/zedrouter \
  github.com/zededa/go-provision/domainmgr \
  github.com/zededa/go-provision/identitymgr \
  github.com/zededa/go-provision/zedmanager \
  github.com/zededa/go-provision/eidregister

RUN cd /opt/zededa/bin ; ln -s /go/bin/* .

# Now building LISP
FROM alpine:latest AS lisp
ENV LISP_URL https://www.dropbox.com/s/gw1gczw8z798q0a/lispers.net-x86-release-0.419.tgz
RUN apk add --no-cache curl gcc linux-headers libc-dev python python-dev libffi-dev openssl-dev
RUN mkdir /lisp ; cd /lisp ; curl --insecure -L $LISP_URL | gzip -dc | tar -xf -
ADD scripts/lisp/RESTART-LISP \
    scripts/lisp/RUN-LISP     \
    scripts/lisp/STOP-LISP    \
    scripts/lisp/pslisp       \
  /lisp/
RUN python /lisp/get-pip.py
RUN pip install -r /lisp/pip-requirements.txt

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
