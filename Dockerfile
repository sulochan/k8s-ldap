FROM golang:1.14.3-alpine AS build

RUN mkdir /app
WORKDIR /app
COPY . /app
RUN go build -o /app/k8s-ldap

RUN apk upgrade --update-cache --available && \
    apk add openssl && \
    rm -rf /var/cache/apk/*

RUN openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout key.pem -out cert.pem

ENTRYPOINT ["/app/k8s-ldap", "--url", "ad.auth.example.com", "--key", "./key.pem", "--cert", "./cert.pem", "--config", "./config.json"]
