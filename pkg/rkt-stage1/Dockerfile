FROM golang:1.11.11-alpine3.8

ENV GO111MODULE=on

RUN apk update && apk add bash git make autoconf gcc acl-dev musl-dev musl-utils libelf-dev linux-headers openssl-dev bc patch busybox-static
#RUN git clone https://github.com/rkt/stage1-xen.git
ADD https://github.com/rkt/stage1-xen/archive/master.zip /tmp
RUN unzip /tmp/master.zip -d /go
COPY 0001-Go-12-upgrade.patch /go/stage1-xen-master
RUN cd /go/stage1-xen-master && patch -p1 < 0001-Go-12-upgrade.patch

RUN cd /go/stage1-xen-master && bash build.sh
