FROM golang:1.14.3-alpine AS build
RUN mkdir /app
WORKDIR /app
COPY . /app
RUN go build -o /out/k8s-ldap

FROM alpine:latest AS ldap
RUN mkdir /app
WORKDIR /app

RUN apk upgrade --update-cache --available && \
    apk add openssl && \
    rm -rf /var/cache/apk/*

RUN openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout key.pem -out cert.pem
COPY --from=build /out/k8s-ldap /app/k8s-ldap
ENTRYPOINT ["/app/k8s-ldap", "--url ad.auth.rackspace.com", "--key key.pem", "--cert cert.pem", "--config config.json"]

