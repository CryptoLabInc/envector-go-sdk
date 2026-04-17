.PHONY: build test vet fmt tidy cover proto proto-lint

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
