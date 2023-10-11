# Use an official Golang runtime as a parent image
FROM golang:1.20.10-alpine3.18 as builder

RUN apk --no-cache add make=4.4.1-r1

# Set the working directory to /go/src/app
WORKDIR /go/src/app

# Copy the current directory contents into the container at /go/src/app
COPY /dockerfile-add-scanner /go/src/app

# Compile the application
RUN make build OUTDIR=/bin

# Deploy the application binary into a lean image
FROM alpine:3.18
RUN apk --no-cache add ca-certificates=20230506-r0 \
  && update-ca-certificates

WORKDIR /bin
COPY --from=builder /bin/dockerfile-add-scanner /bin/dockerfile-add-scanner

CMD ["/bin/dockerfile-add-scanner"]
