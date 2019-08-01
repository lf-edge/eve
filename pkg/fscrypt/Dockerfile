FROM golang:1.12.4-alpine

RUN apk add --no-cache git gcc linux-headers libc-dev util-linux \
                       libpcap-dev make linux-pam-dev m4

RUN mkdir -p $GOPATH/src/github.com/google && \
    cd $GOPATH/src/github.com/google && \
    git clone https://github.com/google/fscrypt
WORKDIR $GOPATH/src/github.com/google/fscrypt

RUN make && make install
