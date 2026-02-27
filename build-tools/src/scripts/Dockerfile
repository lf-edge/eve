ARG GOVER=1.20.1
ARG ZFS_IMAGE
# hadolint ignore=DL3006
FROM ${ZFS_IMAGE} AS zfs
FROM golang:${GOVER}-alpine
ARG USER
ARG GROUP
ARG UID
ARG GID
# all_proxy is the standard proxy definer for socks proxies. Docker build only has built-ins for http_proxy,https_proxy,ftp_proxy,no_proxy
# so we need to declare it explicitly
# this must be an ARG so it doesn't carry through post-build phase
ARG all_proxy
# hadolint ignore=DL3018
RUN apk add --no-cache openssh-client git gcc linux-headers libc-dev util-linux libpcap-dev bash vim make protobuf \
    protobuf-dev sudo tar curl graphviz ttf-freefont patch dnsmasq ca-certificates \
    libintl libtirpc zlib

RUN deluser ${USER} ; delgroup ${GROUP} || :
RUN sed -ie /:${UID}:/d /etc/passwd /etc/shadow ; sed -ie /:${GID}:/d /etc/group || :
RUN addgroup -g ${GID} ${GROUP} && adduser -h /home/${USER} -G ${GROUP} -D -H -u ${UID} ${USER}
RUN echo "${USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USER}

# Install pre-built OpenZFS userspace libraries and tools from eve-zfs package
COPY --from=zfs / /

RUN go install github.com/golang/protobuf/protoc-gen-go@v1.5.2
RUN go install gotest.tools/gotestsum@v1.7.0
RUN go install github.com/seamia/protodot@87817c3d0a8e7af753af15508b51292e941bc7c6
RUN mv /go/bin/protodot /usr/local/bin
RUN mv /go/bin/* /usr/bin
ENV HOME /home/${USER}
ENV GOFLAGS=-mod=vendor
ENV GO111MODULE=on
