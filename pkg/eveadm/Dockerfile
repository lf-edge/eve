FROM golang:1.12.4-alpine as eveadm-build

RUN apk add --no-cache git make

ENV EVEADM_TAG 0.0.6

RUN git clone --branch ${EVEADM_TAG} https://github.com/itmo-eve/eveadm.git

WORKDIR /go/eveadm

RUN make

FROM scratch
ENTRYPOINT []
CMD []
COPY --from=eveadm-build /go/eveadm/eveadm /