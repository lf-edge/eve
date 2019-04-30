ARG GOVER=1.12.4
FROM golang:${GOVER}-alpine
ARG USER
ARG GROUP
ARG UID
ARG GID
RUN apk add --no-cache openssh-client git gcc linux-headers libc-dev util-linux libpcap-dev bash vim make protobuf protobuf-dev sudo
RUN deluser ${USER} ; delgroup ${GROUP} || :
RUN sed -ie /:${UID}:/d /etc/passwd /etc/shadow ; sed -ie /:${GID}:/d /etc/group || :
RUN addgroup -g ${GID} ${GROUP} && adduser -h /home/${USER} -G ${GROUP} -D -H -u ${UID} ${USER}
RUN echo "${USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USER}
RUN go get github.com/golang/dep/cmd/dep 
RUN go get -u github.com/golang/protobuf/protoc-gen-go
RUN go get -u github.com/jstemmer/go-junit-report
RUN mv /go/bin/* /usr/bin
ENV HOME /home/${USER}

