ARG BUILD_FROM
FROM $BUILD_FROM

ADD https://github.com/nginx/njs-acme/releases/download/v1.0.0/acme.js /etc/nginx/js/acme.js
RUN chmod 444 /etc/nginx/js/acme.js

# Setup base
RUN apk add --no-cache nginx nginx-mod-http-js openssl ca-certificates

# Copy data
COPY rootfs /

WORKDIR /
