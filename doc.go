// Package envector is the Go SDK for enVector Cloud.
//
// The surface area is intentionally narrow: enough to drive the retriever
// path (Score + GetMetadata), the capture path (Insert with a local FHE
// encrypt step), and the key/index lifecycle needed to stand a vault up.
// All configuration uses functional options — the Xxx* helpers are the
// only way to populate ClientOption / KeysOption / IndexOption values.
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
// local CGO handle. Bootstrap from disk:
//
//	opts := []envector.KeysOption{
//	    envector.WithKeyPath("vault_keys"),
//	    envector.WithKeyID("vault-key"),
//	    envector.WithKeyPreset("FGb"),
//	    envector.WithKeyEvalMode("ip"),
//	    envector.WithKeyDim(1024),
//	}
//	if !envector.KeysExist(opts...) {
//	    _ = envector.GenerateKeys(opts...)
//	}
//	keys, _ := envector.OpenKeysFromFile(opts...)
//	defer keys.Close()
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
// Client.Index opens or creates an index (idempotent). Insert encrypts
// vectors locally through the bound Keys and streams the ciphertexts;
// Score runs InnerProduct and returns opaque CiphertextScore bytes for
// Keys.Decrypt (or an equivalent vault) to consume.
//
//	idx, _ := client.Index(ctx,
//	    envector.WithIndexName("vault"),
//	    envector.WithIndexKeys(keys),
//	    envector.WithIndexDim(1024),
//	)
//	_, _ = idx.Insert(ctx, envector.InsertRequest{Vectors: vecs, Metadata: md})
//	blobs, _ := idx.Score(ctx, query)
//	scores, shards, _ := keys.Decrypt(blobs[0])
//	meta, _ := idx.GetMetadata(ctx, refs, []string{"metadata"})
//
// # Build tags
//
// By default the FHE primitives resolve to an in-process deterministic
// mock, sufficient for wire-fidelity tests and cross-compilation. Build
// with -tags=libevi to link the real libevi_crypto CGO binding shipped
// under third_party/evi/.
package envector
