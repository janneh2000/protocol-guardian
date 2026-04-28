# AXL node — Go build of gensyn-ai/axl pinned to its supported toolchain.
# We mount the per-instance node-config.json + private.pem at runtime.

FROM golang:1.25.5-alpine AS build
RUN apk add --no-cache git make openssl
WORKDIR /src
RUN git clone --depth=1 https://github.com/gensyn-ai/axl.git .
RUN make build

FROM alpine:3.20
RUN apk add --no-cache openssl ca-certificates
WORKDIR /node
COPY --from=build /src/node /usr/local/bin/axl-node

# Generate a per-container ed25519 key on first run if one isn't mounted.
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 9001 9090
ENTRYPOINT ["/entrypoint.sh"]
