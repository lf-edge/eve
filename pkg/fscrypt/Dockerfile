FROM golang:1.12.4-alpine

RUN apk add --no-cache git=2.20.1-r0 gcc=8.3.0-r0 linux-headers=4.18.13-r1 \
                       libc-dev=0.7.1-r0 make=4.2.1-r2 linux-pam-dev=1.3.0-r0 m4=1.4.18-r1

RUN mkdir -p $GOPATH/src/github.com/google
WORKDIR "$GOPATH"/src/github.com/google
RUN git clone https://github.com/google/fscrypt
WORKDIR "$GOPATH"/src/github.com/google/fscrypt
RUN make && make install
