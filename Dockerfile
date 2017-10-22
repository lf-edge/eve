FROM golang:1.9.1-alpine AS build

ENV LISP_URL https://www.dropbox.com/s/zc6lj8f57e5kk0z/lispers.net-x86-release-0.412.tgz

RUN apk add --no-cache curl git gcc linux-headers libc-dev

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

RUN mkdir /opt/zededa/lisp ; cd /opt/zededa/lisp ; curl --insecure -L $LISP_URL | gzip -dc | tar -xf -

# Second stage of the build is creating a minimalistic container
FROM scratch
COPY --from=build /opt/zededa /opt/zededa
COPY --from=build /go/bin/* /opt/zededa/bin/
WORKDIR /opt/zededa/bin
CMD /bin/ash
