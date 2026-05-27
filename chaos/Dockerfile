# Build container for every stele binary used in the chaos rig.
#
# Two-stage build:
#   1. golang:1.25-alpine builds the binaries with the same flags the
#      release workflow uses (reproducible, no cgo, trimpath).
#   2. The runtime stage is a minimal alpine image with the binaries
#      copied in. Each docker-compose service overrides `command` to
#      select which binary to run.

# ----- build stage -----
# Pinned to 1.25-alpine: matches the floor go.mod sets (OTel SDK
# v1.43 requires >= 1.25). The version is also what test.yml /
# hardening.yml / release.yml use, so dev + CI + chaos rig stay
# byte-identical builds.
FROM golang:1.25-alpine AS build
RUN apk add --no-cache ca-certificates git
WORKDIR /src

# Cache dependencies separately from source.
COPY go.mod go.sum ./
ENV GOTOOLCHAIN=local
RUN go mod download

COPY . .
ENV CGO_ENABLED=0
RUN set -eux; \
    mkdir /out; \
    for cmd in steled stele stele-witness stele-mirror stele-loadgen; do \
        go build -trimpath -buildvcs=false \
            -ldflags='-s -w -buildid= -X main.version=chaos-rig -X main.commit=local' \
            -o /out/$cmd "./cmd/$cmd"; \
    done

# ----- runtime stage -----
FROM alpine:3.19
RUN apk add --no-cache ca-certificates curl jq
WORKDIR /app
COPY --from=build /out/* /usr/local/bin/

# Default to running steled; each docker-compose service overrides
# the command + args + ports it needs.
ENTRYPOINT ["/usr/local/bin/steled"]
CMD ["--help"]
