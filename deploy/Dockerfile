# Production OCI image for stele.
#
# Differences from chaos/Dockerfile:
#
#   - distroless/static runtime (~2MB vs alpine's ~12MB)
#   - non-root user (uid 65532)
#   - explicit OCI annotations for image catalogs
#   - identical reproducible build flags as release.yml
#   - ALL stele binaries in /usr/local/bin; CMD selects via the
#     container's command line. One image serves every role.
#
# HSM note: this image is built with CGO_ENABLED=0, so steled
# --hsm-module will return "no-cgo build cannot generate HSM keys".
# Operators who need PKCS#11 HSM support rebuild with build-arg
# `CGO_ENABLED=1` and use a non-distroless base (alpine + libpkcs11
# at runtime).
#
# Build:
#     docker build -f deploy/Dockerfile -t stele:dev \
#         --build-arg VERSION=v0.1.0 \
#         --build-arg COMMIT=$(git rev-parse HEAD) .
#
# Run (operator):
#     docker run --rm -p 8080:8080 \
#         -v stele-data:/var/lib/stele \
#         -v stele-keys:/var/lib/stele/keys \
#         stele:dev steled --dir /var/lib/stele --init --addr :8080
#
# Run (witness):
#     docker run --rm -p 9090:9090 \
#         -v stele-witness:/var/lib/stele \
#         stele:dev stele-witness --dir /var/lib/stele --id witness-a --addr :9090

ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.20

# ----- build stage -----
FROM golang:${GO_VERSION}-alpine AS build
ARG VERSION=dev
ARG COMMIT=none
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local
RUN mkdir /out && \
    for cmd in steled stele stele-witness stele-mirror stele-cosigner \
               stele-backup stele-export-chain stele-loadgen stele-watcher; do \
        go build -trimpath -buildvcs=false \
            -ldflags="-s -w -buildid= -X main.version=${VERSION} -X main.commit=${COMMIT}" \
            -o "/out/$cmd" "./cmd/$cmd"; \
    done

# ----- runtime stage -----
# distroless/static contains: ca-certs, /etc/passwd with `nonroot`
# uid 65532, no shell, no package manager. Total ~2MB.
FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
ARG COMMIT=none

LABEL org.opencontainers.image.title="stele" \
      org.opencontainers.image.description="Provenance-anchored audit log" \
      org.opencontainers.image.source="https://github.com/desledishant10/stele" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.documentation="https://github.com/desledishant10/stele/blob/main/deploy/QUICKSTART.md"

COPY --from=build --chown=nonroot:nonroot /out/* /usr/local/bin/

# Provide a default data dir owned by `nonroot` so operators don't
# have to chown a mounted volume on every fresh start.
USER nonroot:nonroot
WORKDIR /var/lib/stele

# Default to steled; every other binary is one CMD-override away.
# Users do:  docker run stele:vX steled --help
#            docker run stele:vX stele-witness --help  (etc.)
ENTRYPOINT []
CMD ["steled", "--help"]
