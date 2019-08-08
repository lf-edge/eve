FROM golang:1.11.11-alpine3.8
ENV GO111MODULE=on

# hadolint ignore=DL3018
RUN apk add --no-cache bash git make autoconf gcc acl-dev musl-dev musl-utils libelf-dev linux-headers openssl-dev bc patch busybox-static

ADD https://github.com/rkt/stage1-xen/archive/master.zip /tmp
RUN unzip /tmp/master.zip -d /go
COPY *.patch /go/stage1-xen-master/
WORKDIR /go/stage1-xen-master
RUN for p in *.patch ; do patch -p1 < "$p" ; done

RUN bash build.sh
# We will be using host EVE kernel to launch containers for now
RUN rm -f /go/stage1-xen-master/target/rootfs/kernel || :

RUN go get github.com/appc/spec/actool && \
    go build -o ./aci/actool github.com/appc/spec/actool && \
    ./aci/actool build target stage1-xen.aci
