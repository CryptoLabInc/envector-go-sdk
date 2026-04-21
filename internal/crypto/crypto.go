// Package crypto is the internal FHE primitive boundary. Default() returns
// the cgo Provider that binds the bundled libevi static archives.
package crypto

type CKKSParams struct {
	Preset   string
	DimList  []int
	EvalMode string
}

type KeyGenParams struct {
	CKKSParams
	KeyPath string
	KeyID   string
}

type CKKSContext interface {
	Close() error
}

type Encryptor interface {
	// EncryptMultiple serializes an FHE-encrypted query per output ciphertext.
	// libevi packs multiple plaintext vectors into a smaller set of ciphertexts
	// via CKKS slot packing; the packing ratio is decided internally and not
	// known to the caller. innerCounts[i] reports how many logical input
	// vectors got packed into ciphers[i] — sum(innerCounts) == len(vectors).
	// Callers (Index.Insert) pass innerCounts through to the server so item
	// IDs and metadata slots align with logical vectors, not ciphertexts.
	EncryptMultiple(vectors [][]float32, encodeType string) (ciphers [][]byte, innerCounts []int, err error)
	Close() error
}

type Decryptor interface {
	DecryptScore(scoreProtoBytes []byte) (scores [][]float64, shardIdx []int32, err error)
	Close() error
}

type KeyGenerator interface {
	Generate() error
}

// Provider builds the four primitive handles that a Keys bundle needs.
// Encryptor and Decryptor take the key directory path rather than the raw
// key bytes because the upstream C API only exposes path-based loaders
// (evi_keypack_create_from_path, evi_secret_key_create_from_path).
// Providers read the individual key files off disk themselves.
type Provider interface {
	NewCKKSContext(CKKSParams) (CKKSContext, error)
	NewEncryptor(ctx CKKSContext, keyDir string) (Encryptor, error)
	NewDecryptor(ctx CKKSContext, keyDir string) (Decryptor, error)
	NewKeyGenerator(KeyGenParams) (KeyGenerator, error)
}

func Default() Provider { return cgoProvider{} }
