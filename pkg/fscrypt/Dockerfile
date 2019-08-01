FROM golang:1.12.4-alpine

RUN apk add --no-cache git gcc linux-headers libc-dev util-linux libpcap-dev make linux-pam-dev

RUN git clone https://github.com/google/fscrypt
WORKDIR /go/rkt
RUN git reset --hard tags/v0.2.4
RUN make 
