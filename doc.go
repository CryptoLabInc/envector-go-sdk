// Package envector is the Go SDK for enVector Cloud.
//
// The surface area is intentionally narrow: enough to drive the retriever
// path (Score + GetMetadata), the capture path (Insert with a local FHE
// encrypt step), and the key/index lifecycle needed to stand a deployment
// up. All configuration uses functional options — the With* helpers are
// the only way to populate ClientOption / KeysOption / IndexOption values.
//
// # Client lifecycle
//
// NewClient dials lazily; the underlying gRPC connection is not opened
// until the first RPC. Release with Close.
//
//	client, err := envector.NewClient(
//	    envector.WithAddress("envector.example.com:443"),
//	    envector.WithAccessToken(token),
//	)
//	if err != nil { /* ... */ }
//	defer client.Close()
//
// # Local key bundle
//
// Keys wraps the 3-file FHE material (EncKey / EvalKey / SecKey) behind a
// local CGO handle. WithKeyPath / WithKeyID / WithKeyDim are required;
// missing any of them fails fast at GenerateKeys / OpenKeysFromFile rather
// than deeper inside cgo. Bootstrap from disk:
//
//	opts := []envector.KeysOption{
//	    envector.WithKeyPath("demo_keys"),
//	    envector.WithKeyID("demo-key"),
//	    envector.WithKeyPreset(envector.PresetIP0),     // PresetIP0 | PresetIP1
//	    envector.WithKeyEvalMode(envector.EvalModeRMP), // EvalModeRMP | EvalModeMM
//	    envector.WithKeyDim(1024),
//	}
//	if !envector.KeysExist(opts...) {
//	    _ = envector.GenerateKeys(opts...)
//	}
//	keys, _ := envector.OpenKeysFromFile(opts...)
//	defer keys.Close()
//
// WithKeyParts narrows what OpenKeysFromFile materialises. Encrypt-side
// processes that register + insert typically pass {KeyPartEnc, KeyPartEval};
// decrypt-only processes pass {KeyPartSec}. Omitting the option loads all
// three. Calling Encrypt / Decrypt / RegisterKeys against a bundle that
// did not load the matching part returns ErrKeysNotForEncrypt /
// ErrKeysNotForDecrypt / ErrKeysNotForRegister.
//
// # Server-side key residency
//
// Before Insert, make the bundle resident on the server via ActivateKeys.
// It executes the 4-RPC auto-setup sequence (list, register-if-missing,
// unload-others, load-target) required by servers that allow only one
// resident key at a time.
//
//	_ = client.ActivateKeys(ctx, keys)
//
// # Index operations
//
// Client.Index opens or creates an index (idempotent). Creation requires
// WithIndexKeys — the index dimension is sourced from Keys.Dim() rather
// than configured separately. Index mode is fixed to (cipher index, plain
// query, FLAT, IPOnly) — the only combination this SDK's Insert / Score
// code paths actually exercise. Insert encrypts vectors locally through
// the bound Keys and streams the ciphertexts; Score runs InnerProduct and
// returns opaque CiphertextScore bytes for Keys.Decrypt to consume. Both
// Insert and Score early-fail when the supplied vector length differs
// from Keys.Dim().
//
//	idx, _ := client.Index(ctx,
//	    envector.WithIndexName("demo"),
//	    envector.WithIndexKeys(keys), // dim is sourced from keys.Dim()
//	)
//	_, _ = idx.Insert(ctx, envector.InsertRequest{Vectors: vecs, Metadata: md})
//	blobs, _ := idx.Score(ctx, query)
//	scores, shards, _ := keys.Decrypt(blobs[0])
//	meta, _ := idx.GetMetadata(ctx, refs, []string{"metadata"})
//
// # Native dependency
//
// The FHE primitives are provided by the libevi_crypto CGO binding linked
// against the static archives shipped under third_party/evi/. A working C
// toolchain and OpenSSL 3 (libssl, libcrypto) must be available at build
// time; on macOS install via `brew install openssl@3`, on Debian/Ubuntu
// `apt install libssl-dev`.
package envector
