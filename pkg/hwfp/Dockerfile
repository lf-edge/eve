FROM golang:1.12.4-alpine as build

COPY gohai /gohai

RUN cd /gohai ; go build -mod=vendor .

#FROM scratch
FROM alpine:3.9
WORKDIR /

COPY --from=build /gohai/hwfp /hwfp

ENTRYPOINT ["/hwfp", "/run/hwfp.json"]
CMD ["/hwfp", "/run/hwfp.json"]
