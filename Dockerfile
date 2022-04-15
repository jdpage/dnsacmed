FROM docker.io/library/golang:alpine AS builder
LABEL maintainer="jonathan@sleepingcyb.org"

RUN apk add --update gcc musl-dev git

ENV GOPATH /go
ENV CGO_ENABLED 1
COPY . /src
WORKDIR /src
RUN go build -ldflags="-extldflags=-static" ./cmd/dnsacmed

FROM scratch

COPY --from=builder /src/dnsacmed /bin/dnsacmed

VOLUME ["/etc/dnsacmed", "/var/lib/dnsacmed"]
ENTRYPOINT ["/bin/dnsacmed"]
EXPOSE 53 80 443
EXPOSE 53/udp
