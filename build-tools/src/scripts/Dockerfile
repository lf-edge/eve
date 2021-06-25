ARG GOVER=1.15.3
FROM golang:${GOVER}-alpine
ARG USER
ARG GROUP
ARG UID
ARG GID
# all_proxy is the standard proxy definer for socks proxies. Docker build only has built-ins for http_proxy,https_proxy,ftp_proxy,no_proxy
# so we need to declare it explicitly
# this must be an ARG so it doesn't carry through post-build phase
ARG all_proxy
RUN apk add --no-cache openssh-client git gcc linux-headers libc-dev util-linux libpcap-dev bash vim make protobuf protobuf-dev sudo tar curl graphviz ttf-freefont
RUN deluser ${USER} ; delgroup ${GROUP} || :
RUN sed -ie /:${UID}:/d /etc/passwd /etc/shadow ; sed -ie /:${GID}:/d /etc/group || :
RUN addgroup -g ${GID} ${GROUP} && adduser -h /home/${USER} -G ${GROUP} -D -H -u ${UID} ${USER}
RUN echo "${USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USER}
RUN go get github.com/golang/dep/cmd/dep
RUN go get -u github.com/golang/protobuf/protoc-gen-go
RUN go get -u gotest.tools/gotestsum
RUN go get -u github.com/seamia/protodot
RUN mv /go/bin/protodot /usr/local/bin
RUN mv /go/bin/* /usr/bin
ENV HOME /home/${USER}
ENV GOFLAGS=-mod=vendor
ENV GO111MODULE=on
