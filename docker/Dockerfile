FROM docker.io/library/golang:1.20 AS builder

WORKDIR /benchy

COPY . .
# build
RUN go generate ./...
RUN CGO_ENABLED=1 go build -o bin/ -tags='netgo timetzdata' -trimpath -a -ldflags '-s -w -linkmode external -extldflags "-static"'  ./cmd/benchyd

FROM docker.io/library/alpine:3
LABEL maintainer="The Sia Foundation <info@sia.tech>" \
      org.opencontainers.image.description.vendor="The Sia Foundation" \
      org.opencontainers.image.description="A benchyd container - easily benchmark sia hosts" \
      org.opencontainers.image.source="https://github.com/SiaFoundation/host-benchmark" \
      org.opencontainers.image.licenses=MIT

ENV PUID=0
ENV PGID=0

ENV BENCHY_SEED=

# copy binary and prepare data dir.
COPY --from=builder /benchy/bin/* /usr/bin/
VOLUME [ "/data" ]

# API port
EXPOSE 8484/tcp
# RPC port
EXPOSE 9981/tcp

USER ${PUID}:${PGID}

ENTRYPOINT [ "benchyd", "--dir", "/data", "--api.addr", ":8484" ]