# All targets link the libevi cgo provider against the static archives
# bundled under third_party/evi/. Build prerequisites:
#   - C toolchain (cc/clang/gcc) on PATH
#   - OpenSSL 3 (libssl, libcrypto) — macOS: `brew install openssl@3`,
#     Debian/Ubuntu: `apt install libssl-dev`
# CGO_ENABLED=1 is set explicitly so cross-compile environments don't
# silently produce a non-functional binary.

.PHONY: build test vet fmt tidy cover proto proto-lint

export CGO_ENABLED=1

build:
	go build ./...

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
