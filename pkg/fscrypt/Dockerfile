FROM golang:1.12.4-alpine as build

RUN apk add --no-cache git=2.20.2-r0 gcc=8.3.0-r0 linux-headers=4.18.13-r1 \
                       libc-dev=0.7.1-r0 make=4.2.1-r2 linux-pam-dev=1.3.0-r0 \
                       m4=1.4.18-r1 findutils=4.6.0-r1

RUN mkdir -p /go/src/github.com/google
WORKDIR /go/src/github.com/google
RUN git clone https://github.com/google/fscrypt
WORKDIR /go/src/github.com/google/fscrypt
RUN git reset --hard b41569d397d3e66099cde07d8eef36b2f42dd0ec
COPY fscrypt-patch.diff fscrypt-patch.diff
RUN patch -p1 < fscrypt-patch.diff && \
    make && make install

FROM scratch
COPY --from=build /usr/local/bin/fscrypt /
