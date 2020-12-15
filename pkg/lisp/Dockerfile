ARG GOVER=1.12.4
FROM golang:${GOVER}-alpine as build
RUN apk add --no-cache           \
        gcc=8.3.0-r0             \
        linux-headers=4.18.13-r1 \
        libc-dev=0.7.1-r0        \
        libpcap-dev=1.9.0-r1

ENV GOFLAGS=-mod=vendor
ENV GO111MODULE=on
ENV CGO_ENABLED=1

COPY ./  /lisp/
WORKDIR /lisp
RUN go build -mod=vendor -o lisp-ztr ./cmd/lisp-ztr
RUN strip lisp-ztr

FROM alpine:3.11 AS lisp
ENV LISP_VERSION=release-0.488

ADD https://github.com/farinacci/lispers.net/archive/${LISP_VERSION}.tar.gz /tmp/
ADD patches /tmp/patches
ADD pyfakes /usr/bin/pyflakes

RUN apk add --no-cache           \
        py2-pip=18.1-r0          \
        gcc=9.3.0-r0             \
        linux-headers=4.19.36-r0 \
        libc-dev=0.7.2-r0        \
        python2-dev=2.7.18-r0    \
        libffi-dev=3.2.1-r6      \
        openssl-dev=1.1.1i-r0    \
        libpcap-dev=1.9.1-r0
RUN tar -C /tmp -xzvf /tmp/${LISP_VERSION}.tar.gz && \
    cd /tmp/lispers.net-${LISP_VERSION} && \
    for p in /tmp/patches/* ; do patch -p1 < $p ; done && \
    cd build ; python make-release.py dev && \
    mkdir /lisp ; tar -C /lisp -xzvf latest/lispers.net.tgz

RUN pip install --upgrade pip && pip install -r /lisp/pip-requirements.txt
RUN apk del py2-pip

# Putting it all together
FROM alpine:3.11

RUN apk add --no-cache     \
        libffi=3.2.1-r6    \
        libpcap=1.9.1-r0   \
        python2=2.7.18-r0  \
        openssl=1.1.1i-r0  \
        iproute2=5.4.0-r1  \
        keyutils=1.6.1-r0  \
        tini=0.18.0-r0

COPY --from=lisp /lisp /lisp/
COPY --from=lisp /usr/bin/pydoc /usr/bin/smtpd.py /usr/bin/
RUN echo workaround for https://github.com/moby/moby/issues/37965
COPY --from=lisp /usr/lib/python2.7/site-packages /usr/lib/python2.7/site-packages 

COPY --from=build /lisp/lisp-ztr /lisp/

ADD rootfs/ /

EXPOSE 8080

WORKDIR /lisp
ENTRYPOINT []
CMD ["/sbin/tini", "/init.sh"]
