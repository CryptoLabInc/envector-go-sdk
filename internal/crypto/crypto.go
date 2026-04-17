// Package crypto is the internal FHE primitive boundary. Default() returns
// a Provider chosen by build tag: the libevi tag swaps in the CGO binding,
// otherwise a deterministic mock is used.
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

type Provider interface {
	NewCKKSContext(CKKSParams) (CKKSContext, error)
	NewEncryptor(CKKSContext, []byte) (Encryptor, error)
	NewDecryptor(CKKSContext, []byte) (Decryptor, error)
	NewKeyGenerator(KeyGenParams) (KeyGenerator, error)
}

func Default() Provider { return defaultProvider() }
