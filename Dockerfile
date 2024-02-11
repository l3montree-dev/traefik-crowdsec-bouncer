ARG GOLANG_VERSION=1.22

# Building bouncer
FROM golang:$GOLANG_VERSION as build-env

# Copying source
WORKDIR /go/src/app
COPY . /go/src/app

# Installing dependencies
RUN go get -d -v ./...

# Compiling
RUN go build -o /go/bin/app

FROM gcr.io/distroless/base:nonroot
COPY --from=build-env --chown=nonroot:nonroot /go/bin/app /
# Run as a non root user.
USER nonroot

# Run app
CMD ["/app"]
