# syntax=docker/dockerfile:1.7

# The build stage always runs on the build host's platform and cross-compiles
# via GOARCH, so multi-arch images need no QEMU emulation.
#
# Base images are pinned by digest (the tag is kept for readability);
# Dependabot bumps both. The golang image sets GOTOOLCHAIN=local, so released
# binaries are built with this image's Go, not the go.mod toolchain line.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
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

FROM gcr.io/distroless/static:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
WORKDIR /
COPY --from=build /out/sigillum /sigillum
USER 65532:65532
ENTRYPOINT ["/sigillum"]
