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
	EncryptMultiple(vectors [][]float32, encodeType string) ([][]byte, error)
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
