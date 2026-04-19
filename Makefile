# sigillum — single-image, dual-mode build
SHELL := /usr/bin/env bash

VERSION ?= 0.1.0
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LD_FLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

GO       ?= go
PKG      := ./...
BIN_DIR  ?= bin
LOCALBIN ?= $(CURDIR)/bin

CONTROLLER_GEN_VERSION ?= v0.16.5
ENVTEST_VERSION       ?= release-0.18
ENVTEST_K8S_VERSION   ?= 1.30.0

CONTROLLER_GEN := $(LOCALBIN)/controller-gen
ENVTEST        := $(LOCALBIN)/setup-envtest

IMAGE_REPO ?= ghcr.io/se-wo/sigillum
IMAGE_TAG  ?= $(VERSION)

.PHONY: all
all: build

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: fmt
fmt:
	$(GO) fmt $(PKG)

.PHONY: vet
vet:
	$(GO) vet $(PKG)

.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LD_FLAGS)' -o $(BIN_DIR)/sigillum ./cmd/sigillum

.PHONY: test
test: manifests generate fmt vet envtest
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" \
	$(GO) test -tags=envtest $(PKG) -coverprofile=cover.out

.PHONY: test-unit
test-unit:
	$(GO) test -short $(PKG)

.PHONY: test-envtest
test-envtest: envtest
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" \
	$(GO) test -tags=envtest ./internal/controller/... -v

.PHONY: manifests
manifests: controller-gen
	$(CONTROLLER_GEN) crd:allowDangerousTypes=true rbac:roleName=sigillum-controller webhook \
		paths=./api/... paths=./internal/controller/... paths=./internal/webhook/... \
		output:crd:artifacts:config=config/crd/bases \
		output:rbac:artifacts:config=config/rbac \
		output:webhook:artifacts:config=config/webhook
	@cp -f config/crd/bases/*.yaml charts/sigillum/crds/

.PHONY: generate
generate: controller-gen
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt paths=./api/...

.PHONY: docker-build
docker-build:
	docker build -t $(IMAGE_REPO):$(IMAGE_TAG) .

.PHONY: kind-load
kind-load:
	kind load docker-image $(IMAGE_REPO):$(IMAGE_TAG)

.PHONY: e2e
e2e:
	$(GO) test -tags=e2e ./test/e2e/... -timeout=20m -v

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: controller-gen
controller-gen: $(LOCALBIN)
	@test -x $(CONTROLLER_GEN) || GOBIN=$(LOCALBIN) $(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

.PHONY: envtest
envtest: $(LOCALBIN)
	@test -x $(ENVTEST) || GOBIN=$(LOCALBIN) $(GO) install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION)

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) cover.out
