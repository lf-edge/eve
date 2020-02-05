ARG GOVER=1.12.4
FROM golang:${GOVER}-alpine as build
RUN apk add --no-cache git gcc linux-headers libc-dev util-linux libpcap-dev make

# These three are supporting rudimentary cross-build capabilities.
# The only one supported so far is cross compiling for aarch64 on x86
ENV GOFLAGS=-mod=vendor
ENV GO111MODULE=on
ENV CGO_ENABLED=1

COPY ./  /lisp/
WORKDIR /lisp
RUN go build -mod=vendor -o lisp-ztr ./cmd/lisp-ztr
RUN strip lisp-ztr

FROM alpine:3.8 AS lisp
ENV LISP_VERSION=release-0.488

ADD https://github.com/farinacci/lispers.net/archive/${LISP_VERSION}.tar.gz /tmp/
ADD patches /tmp/patches

RUN apk add --no-cache py2-pyflakes py2-pip gcc linux-headers  \
    libc-dev python python-dev libffi-dev openssl-dev libpcap-dev
RUN ln -s pyflakes-2 /usr/bin/pyflakes
RUN tar -C /tmp -xzvf /tmp/${LISP_VERSION}.tar.gz && \
    cd /tmp/lispers.net-${LISP_VERSION} && \
    for p in /tmp/patches/* ; do patch -p1 < $p ; done && \
    cd build ; python make-release.py dev && \
    mkdir /lisp ; tar -C /lisp -xzvf latest/lispers.net.tgz

RUN pip install --upgrade pip && pip install -r /lisp/pip-requirements.txt
RUN apk del py2-pip py2-pyflakes

# Putting it all together
FROM alpine:3.8

RUN apk add --no-cache python libffi openssl libpcap iproute2 tini

COPY --from=lisp /lisp /lisp/
COPY --from=lisp /usr/bin/pydoc /usr/bin/smtpd.py /usr/bin/
COPY --from=lisp /usr/lib/python2.7/site-packages /usr/lib/python2.7/site-packages 

COPY --from=build /lisp/lisp-ztr /lisp/

ADD rootfs/ /

EXPOSE 8080

WORKDIR /lisp
ENTRYPOINT []
CMD ["/sbin/tini", "/init.sh"]
