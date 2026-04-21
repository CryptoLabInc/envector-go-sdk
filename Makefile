# All targets link the libevi cgo provider against the static archives
# bundled under third_party/evi/. Build prerequisites:
#   - C toolchain (cc/clang/gcc) on PATH
#   - OpenSSL 3 (libssl, libcrypto) — macOS: `brew install openssl@3`,
#     Debian/Ubuntu: `apt install libssl-dev`
# CGO_ENABLED=1 is set explicitly so cross-compile environments don't
# silently produce a non-functional binary.

.PHONY: build test test-e2e vet fmt tidy cover proto proto-lint

export CGO_ENABLED=1

# Defaults for `make test-e2e`. Override per-invocation:
#   make test-e2e ENVECTOR_ADDR=cluster.example.com:443 ENVECTOR_TOKEN=...
# Unset to exercise the skip path:
#   make test-e2e ENVECTOR_ADDR=
# ENVECTOR_INSECURE=1 disables TLS; any other value (or unset) keeps TLS on.
ENVECTOR_ADDR     ?= localhost:50051
ENVECTOR_TOKEN    ?= fake-token-abcde-12345
ENVECTOR_INSECURE ?= false
export ENVECTOR_ADDR ENVECTOR_TOKEN ENVECTOR_INSECURE

build:
	go build ./...

test-e2e:
	cd tests && go test -tags=e2e -timeout 10m -parallel 1 ./e2e/...

proto:
	buf generate

proto-lint:
	buf lint
	buf format -d

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

cover:
	go test -race -coverprofile=coverage.txt -covermode=atomic ./...
