# envector-go-sdk e2e tests

Blackbox integration suite for the SDK. Isolated as a separate Go module
with `replace github.com/CryptoLabInc/envector-go-sdk => ../`, so tests
can only touch the public API surface — attempts to reach into
`internal/` fail to resolve at compile time.

## Running

From the repo root:

```sh
make test-e2e
```

The Makefile ships sensible defaults for a local envector dev instance
(see the env block at the top of `../Makefile`). Override per invocation:

```sh
make test-e2e \
  ENVECTOR_ADDR=cluster.example.com:443 \
  ENVECTOR_TOKEN=<bearer-token>
```

Exercise the skip path (every scenario `t.Skip`s when the address is
blank — useful to confirm CI doesn't red-flag a missing endpoint):

```sh
make test-e2e ENVECTOR_ADDR=
```

## Environment variables

| Name                | Default                  | Meaning                                            |
| ------------------- | ------------------------ | -------------------------------------------------- |
| `ENVECTOR_ADDR`     | `localhost:50051`        | `host:port`. Empty → all scenarios `t.Skip`.       |
| `ENVECTOR_TOKEN`    | `fake-token-abcde-12345` | Bearer token; sent as `authorization: Bearer ...`. |
| `ENVECTOR_INSECURE` | `false`                  | Set to `1` to dial without TLS. Any other value keeps TLS on. |

## Scenarios

| File                     | Test                                       | What it verifies                                          |
| ------------------------ | ------------------------------------------ | --------------------------------------------------------- |
| `connectivity_test.go`   | `TestConnectivity_GetKeysList`             | TLS handshake + bearer auth + one trivial RPC. Canary.    |
| `keys_test.go`           | `TestKeys_ActivateListDelete`              | `ActivateKeys` persists on server; `DeleteKeys` removes.  |
| `index_test.go`          | `TestIndex_CreateListDrop`                 | Index create/drop persists; dim flows from `Keys.Dim()`.  |
| `capture_test.go`        | `TestCapture_SmallBatch`                   | Single-frame `Insert` round-trips.                        |
|                          | `TestCapture_LargeBatch`                   | >1 MiB `Insert` chunked and reassembled server-side.      |
| `retrieve_test.go`       | `TestRetrieve_ScoreAndMetadataRoundTrip`   | FHE score correctness (noise ≤ 1e-2) + metadata lookup.   |

## Cleanup discipline

Every server resource a run creates is prefixed with a fresh per-process
`runID` (e.g. `ea3f2k1`, `ea3f2i2`). Names are deliberately compact
(≤20 chars) to fit aggressive server-side length caps on key/index IDs;
`k`/`i` are used as kind markers since they sit outside the hex alphabet
and can't be confused with another run's `runID`. `t.Cleanup` tears each
resource down in LIFO order (index → keys → local handles). A `TestMain`
sweeper runs after the suite to best-effort delete any `runID`-prefixed
residuals that panics or hard-kill left behind, and logs the count.

Tests run serially (`-parallel 1`) — the server permits only one loaded
key at a time, and `ActivateKeys` is globally serialized anyway.

Because the e2e cluster is a dedicated isolated instance (no production
traffic co-resident), mutation is free — this pipeline exists for CI
hygiene (parallel-run isolation, long-term residue control), not prod
safety.

## Adding a scenario

1. Prefer an existing file grouped by lifecycle stage (connectivity /
   keys / index / capture / retrieve). Add a new `Test*` func rather
   than a whole new file unless the stage isn't represented yet.
2. Use the shared helpers in `e2e/helpers_test.go`:
   `newTestClient`, `newTestKeys`, `newTestIndex`,
   `activateKeysWithCleanup`, `sampleVectors`, `approxEqual`, `contains`.
   They handle env-skip, unique naming, and cleanup registration.
3. Every file carries `//go:build e2e`. Don't drop the tag — it's what
   keeps the suite out of `go build ./...` for consumers who vendor
   the `tests/` module accidentally.
4. Server-side resource names must route through `uniqueName(kind)` so
   the sweeper backstop can find them after a crash.
