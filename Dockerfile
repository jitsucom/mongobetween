FROM golang:1.25 as build
WORKDIR /go/src
COPY . .
RUN CGO_ENABLED=0 make

FROM debian:bookworm-slim

RUN apt-get update -y
RUN apt-get install -y ca-certificates

ENV TZ=UTC

COPY --from=build /go/src/bin/mongobetween /mongobetween
ENTRYPOINT ["/mongobetween"]
