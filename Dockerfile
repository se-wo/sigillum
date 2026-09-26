# syntax=docker/dockerfile:1.7

# The build stage always runs on the build host's platform and cross-compiles
# via GOARCH, so multi-arch images need no QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS build
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

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=build /out/sigillum /sigillum
USER 65532:65532
ENTRYPOINT ["/sigillum"]
