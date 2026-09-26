# syntax=docker/dockerfile:1.7

# The build stage always runs on the build host's platform and cross-compiles
# via GOARCH, so multi-arch images need no QEMU emulation.
#
# Base images are pinned by digest (the tag is kept for readability);
# Dependabot bumps both. The golang image sets GOTOOLCHAIN=local, so released
# binaries are built with this image's Go, not the go.mod toolchain line.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG TARGETOS=linux
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /out/sigillum ./cmd/sigillum

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
WORKDIR /
COPY --from=build /out/sigillum /sigillum
USER 65532:65532
ENTRYPOINT ["/sigillum"]
