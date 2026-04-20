# envector-go-sdk

Go client for **enVector Cloud** — vector search over FHE-encrypted
embeddings. The surface covers the retriever path (`Score` +
`GetMetadata`), the capture path (`Insert` with a local FHE encrypt
step), and the key/index lifecycle needed to stand a deployment up.

Status: pre-1.0 (`Version = "0.0.0"`).

## Requirements

This SDK binds the libevi FHE primitives via cgo. Every machine that
compiles a binary depending on `envector-go-sdk` (not just contributors)
needs the following:

- Go 1.25.9 or newer (pinned in `go.mod`)
- C toolchain (clang or gcc)
- OpenSSL 3 — `libssl` + `libcrypto`, dev headers included
- C++ standard library (`libc++` on macOS, `libstdc++` on Linux/Windows)
- A host platform with a bundled libevi slice in `third_party/evi/`:
  - `darwin/arm64`, `darwin/amd64`
  - `linux/amd64`, `linux/arm64`
  - `windows/amd64`

The libevi static archives (`libevi_c_api.a`, `libevi_crypto.a`,
`libdeb.a`, `libalea.a`) are vendored in-tree, so no external libevi
download is required.

### Per-platform install

| Platform | One-shot install |
| -------- | ---------------- |
| macOS (Apple Silicon / Intel) | `xcode-select --install && brew install openssl@3` |
| Debian / Ubuntu | `apt install build-essential libssl-dev` |
| RHEL / Fedora | `dnf install gcc-c++ make openssl-devel` |
| Alpine | `apk add build-base openssl-dev` |
| Windows | MSYS2 mingw64 shell: `pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl` |

Verify the toolchain is wired up correctly:

```sh
go version                          # >= 1.25.9
cc --version                        # clang or gcc
pkg-config --modversion openssl     # >= 3.0
```

### Cross-compilation

cgo requires the **target** platform's C toolchain and sysroot — setting
`GOOS` / `GOARCH` alone is not sufficient. For multi-platform releases,
build on a native host (or container) per target rather than relying on
in-place cross-compilation.

### Unsupported platforms

`linux/386`, `linux/riscv64`, FreeBSD, etc. have no libevi slice in
`third_party/evi/` and will not link. Adding a new platform requires
vendoring a matching libevi archive set first; see
`scripts/refresh-evi.sh`.

## Install

```sh
go get github.com/CryptoLabInc/envector-go-sdk
```

## Quick start

```go
package main

import (
    "context"
    "log"

    "github.com/CryptoLabInc/envector-go-sdk"
)

func main() {
    ctx := context.Background()

    client, err := envector.NewClient(
        envector.WithAddress("envector.example.com:443"),
        envector.WithAccessToken("..."),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    keyOpts := []envector.KeysOption{
        envector.WithKeyPath("demo_keys"),
        envector.WithKeyID("demo-key"),
        envector.WithKeyPreset(envector.PresetIP0),     // PresetIP0 | PresetIP1
        envector.WithKeyEvalMode(envector.EvalModeRMP), // EvalModeRMP | EvalModeMM
        envector.WithKeyDim(128),
    }
    if !envector.KeysExist(keyOpts...) {
        if err := envector.GenerateKeys(keyOpts...); err != nil {
            log.Fatal(err)
        }
    }
    keys, err := envector.OpenKeysFromFile(keyOpts...)
    if err != nil {
        log.Fatal(err)
    }
    defer keys.Close()

    // Make the bundle resident on the server (auto-runs the
    // list / register-if-missing / unload-others / load sequence).
    if err := client.ActivateKeys(ctx, keys); err != nil {
        log.Fatal(err)
    }

    idx, err := client.Index(ctx,
        envector.WithIndexName("demo"),
        envector.WithIndexKeys(keys), // dim is taken from keys.Dim()
    )
    if err != nil {
        log.Fatal(err)
    }

    // Capture: vectors are FHE-encrypted locally then streamed.
    _, err = idx.Insert(ctx, envector.InsertRequest{
        Vectors:  [][]float32{{0.1, 0.2 /* ... */}},
        Metadata: []string{`{"doc":"hello"}`},
    })
    if err != nil {
        log.Fatal(err)
    }

    // Retrieve: server returns ciphertext scores; decrypt locally.
    blobs, err := idx.Score(ctx, []float32{0.1, 0.2 /* ... */})
    if err != nil {
        log.Fatal(err)
    }
    for _, blob := range blobs {
        scores, shards, err := keys.Decrypt(blob)
        if err != nil {
            log.Fatal(err)
        }
        _ = scores
        _ = shards
    }
}
```

Full API reference: <https://pkg.go.dev/github.com/CryptoLabInc/envector-go-sdk>

## Loading only the keys you need

`OpenKeysFromFile` materialises all three key parts (EncKey, EvalKey,
SecKey) by default. Pass `WithKeyParts(...)` to opt in to a subset — the
omitted parts simply aren't loaded into Go / cgo memory.

| Role | Parts | What works |
| ---- | ----- | ---------- |
| Encrypt + register (capture client) | `KeyPartEnc, KeyPartEval` | `keys.Encrypt`, `client.RegisterKeys`, `client.ActivateKeys`, `idx.Insert` |
| Encrypt only (key already registered server-side) | `KeyPartEnc` | `keys.Encrypt`, `idx.Insert` |
| Decrypt only (vault) | `KeyPartSec` | `keys.Decrypt` |
| Default (all parts) | omit `WithKeyParts` | everything |

Calling a method whose required part is missing returns
`ErrKeysNotForEncrypt`, `ErrKeysNotForDecrypt`, or `ErrKeysNotForRegister`
respectively — fail-fast at the SDK boundary instead of deeper inside cgo
or the server.

```go
// Decrypt-only vault process
keys, _ := envector.OpenKeysFromFile(append(keyOpts,
    envector.WithKeyParts(envector.KeyPartSec))...)
defer keys.Close()
scores, shards, _ := keys.Decrypt(scoreBlob)
```

At dim 1024 / RMP this skips loading a ~4 MiB EvalKey buffer and the cgo
KeyPack into memory; the savings scale roughly linearly with dim.

## Building from source

```sh
git clone https://github.com/CryptoLabInc/envector-go-sdk.git
cd envector-go-sdk
make build
make test
```

| Target | Action |
| ------ | ------ |
| `make build` | `go build ./...` |
| `make test` | `go test ./...` |
| `make vet` | `go vet ./...` |
| `make fmt` | `gofmt -w .` |
| `make tidy` | `go mod tidy` |
| `make cover` | race-enabled coverage profile |
| `make proto` | regenerate gRPC stubs (requires [`buf`](https://buf.build/)) |
| `make proto-lint` | lint + format check the `.proto` sources |

`CGO_ENABLED=1` is exported by the Makefile so cross-compile environments
do not silently produce a non-functional binary.

## Refreshing the bundled libevi archives

`third_party/evi/` is regenerated from upstream releases via:

```sh
scripts/refresh-evi.sh
```

See `third_party/evi/PROVENANCE` for the source revision pinned in the
current bundle.
