FROM lfedge/eve-alpine:6.7.0 AS build
ENV BUILD_PKGS gcc linux-headers libc-dev libpcap-dev go python2-dev libffi-dev openssl-dev patch
ENV PKGS libffi libpcap python2 openssl iproute2 keyutils tini
RUN eve-alpine-deploy.sh

ENV LISP_VERSION=release-0.488
ENV BUILD_DIR=/lispers.net-${LISP_VERSION}

ADD https://github.com/farinacci/lispers.net/archive/${LISP_VERSION}.tar.gz /tmp/
ADD https://bootstrap.pypa.io/pip/2.7/get-pip.py /tmp/
COPY patches /tmp/patches
COPY pyfakes /usr/bin/pyflakes

WORKDIR ${BUILD_DIR}
RUN tar -C ${BUILD_DIR}/.. -xzvf "/tmp/${LISP_VERSION}.tar.gz"
RUN for p in /tmp/patches/* ; do patch -p1 < "$p" ; done
WORKDIR ${BUILD_DIR}/build
RUN python make-release.py dev
WORKDIR /lisp
RUN tar -xzvf ${BUILD_DIR}/build/latest/lispers.net.tgz

RUN python /tmp/get-pip.py
RUN pip install -r /lisp/pip-requirements.txt

ENV GOFLAGS=-mod=vendor
ENV GO111MODULE=on
ENV CGO_ENABLED=1

COPY ./  /lisp-go/
WORKDIR /lisp-go
RUN go build -mod=vendor -o /lisp/lisp-ztr ./cmd/lisp-ztr
RUN strip /lisp/lisp-ztr

WORKDIR /out
RUN mv /lisp .
RUN mv /usr/bin/pydoc /usr/bin/smtpd.py usr/bin/
RUN mv /usr/lib/python2.7/site-packages usr/lib/python2.7/site-packages

COPY rootfs/ ./

# Putting it all together
FROM scratch
COPY --from=build /out/ /

EXPOSE 8080

WORKDIR /lisp
ENTRYPOINT []
CMD ["/sbin/tini", "/init.sh"]
