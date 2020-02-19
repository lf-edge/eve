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

RUN echo da
RUN apk add --no-cache \
        libffi=3.2.1-r4    \
        libpcap=1.8.1-r1   \
        python=2.7.15-r3   \
        openssl=1.0.2u-r0  \
        iproute2=4.13.0-r0 \
        tini=0.18.0-r0     \
        keyutils=1.5.10-r0

COPY --from=lisp /lisp /lisp/
COPY --from=lisp /usr/bin/pydoc /usr/bin/smtpd.py /usr/bin/
COPY --from=lisp /usr/lib/python2.7/site-packages /usr/lib/python2.7/site-packages 

COPY --from=build /lisp/lisp-ztr /lisp/

ADD rootfs/ /

EXPOSE 8080

WORKDIR /lisp
ENTRYPOINT []
CMD ["/sbin/tini", "/init.sh"]
