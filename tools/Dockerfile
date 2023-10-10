# Use an official Golang runtime as a parent image
FROM golang:1.20.1 as builder

# Set the working directory to /go/src/app
WORKDIR /go/src/app

# Copy the current directory contents into the container at /go/src/app
COPY /dockerfile-add-scanner /go/src/app

# Install any needed dependencies
RUN go get -d -v ./...

# Compile the application
RUN GOOS=linux CGO_ENABLED=0 go build -o /bin/dockerfile-add-scanner

# Deploy the application binary into a lean image
FROM scratch

WORKDIR /bin
COPY --from=builder /bin/dockerfile-add-scanner /bin/dockerfile-add-scanner

CMD ["/bin/dockerfile-add-scanner"]
