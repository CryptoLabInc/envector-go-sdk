package envector

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CryptoLabInc/envector-go-sdk/internal/crypto"
)

const (
	encKeyFile  = "EncKey.json"
	evalKeyFile = "EvalKey.json"
	secKeyFile  = "SecKey.json"
)

type keysOptions struct {
	Path     string
	KeyID    string
	Preset   string
	EvalMode string
	Dim      int
}

// KeysOption configures KeysExist, GenerateKeys and OpenKeysFromFile.
// Apply via the With* helpers below.
type KeysOption func(*keysOptions)

func WithKeyPath(p string) KeysOption      { return func(o *keysOptions) { o.Path = p } }
func WithKeyID(id string) KeysOption       { return func(o *keysOptions) { o.KeyID = id } }
func WithKeyPreset(p string) KeysOption    { return func(o *keysOptions) { o.Preset = p } }
func WithKeyEvalMode(m string) KeysOption  { return func(o *keysOptions) { o.EvalMode = m } }
func WithKeyDim(d int) KeysOption          { return func(o *keysOptions) { o.Dim = d } }

func buildKeysOptions(opts []KeysOption) keysOptions {
	var o keysOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// Keys is the local side of a 3-file FHE key bundle (EncKey / EvalKey /
// SecKey). It wraps a shared CKKS context together with an Encryptor and
// Decryptor derived from the bundle; EvalKey bytes are retained for
// Client.RegisterKeys uploads. Keys have no server affinity until
// Client.ActivateKeys is called.
type Keys struct {
	id           string
	ckks         crypto.CKKSContext
	enc          crypto.Encryptor
	dec          crypto.Decryptor
	evalKeyBytes []byte
	closed       bool
	activated    *Client
}

// ID returns the key identifier carried by the bundle. The server uses
// this string in RegisterKeys / LoadKeys / UnloadKeys / DeleteKeys.
func (k *Keys) ID() string { return k.id }

func (k *Keys) Close() error {
	if k == nil || k.closed {
		return nil
	}
	k.closed = true
	if k.enc != nil {
		_ = k.enc.Close()
	}
	if k.dec != nil {
		_ = k.dec.Close()
	}
	if k.ckks != nil {
		_ = k.ckks.Close()
	}
	return nil
}

// Encrypt runs the local FHE encrypt stage and returns one serialized
// Query byte slice per input vector, ready for Index.Insert.
func (k *Keys) Encrypt(vectors [][]float32) ([][]byte, error) {
	if k == nil || k.closed {
		return nil, ErrKeysClosed
	}
	return k.enc.EncryptMultiple(vectors, "item")
}

// Decrypt unpacks a CiphertextScore blob produced by Index.Score into
// per-slot score vectors and their matching shard indices. The call is
// local only; no Client is required.
func (k *Keys) Decrypt(blob []byte) (scores [][]float64, shardIdx []int32, err error) {
	if k == nil || k.closed {
		return nil, nil, ErrKeysClosed
	}
	return k.dec.DecryptScore(blob)
}

// KeysExist reports whether the 3-file bundle (EncKey.json, EvalKey.json,
// SecKey.json) is present under WithKeyPath.
func KeysExist(opts ...KeysOption) bool {
	o := buildKeysOptions(opts)
	if o.Path == "" {
		return false
	}
	for _, name := range []string{encKeyFile, evalKeyFile, secKeyFile} {
		if _, err := os.Stat(filepath.Join(o.Path, name)); err != nil {
			return false
		}
	}
	return true
}

// GenerateKeys writes a fresh 3-file bundle at WithKeyPath via the active
// crypto provider. Returns ErrKeysAlreadyExist when any of the three
// files is already present; GenerateKeys never overwrites existing keys.
func GenerateKeys(opts ...KeysOption) error {
	o := buildKeysOptions(opts)
	if o.Path == "" {
		return fmt.Errorf("envector: WithKeyPath required")
	}
	if KeysExist(opts...) {
		return ErrKeysAlreadyExist
	}
	gen, err := crypto.Default().NewKeyGenerator(crypto.KeyGenParams{
		CKKSParams: crypto.CKKSParams{
			Preset:   o.Preset,
			DimList:  []int{o.Dim},
			EvalMode: o.EvalMode,
		},
		KeyPath: o.Path,
		KeyID:   o.KeyID,
	})
	if err != nil {
		return fmt.Errorf("envector: new key generator: %w", err)
	}
	return gen.Generate()
}

// OpenKeysFromFile loads the 3-file bundle at WithKeyPath and builds the
// Encryptor + Decryptor pair backing a Keys handle. Returns ErrKeysNotFound
// when the bundle is absent.
func OpenKeysFromFile(opts ...KeysOption) (*Keys, error) {
	o := buildKeysOptions(opts)
	if o.Path == "" {
		return nil, fmt.Errorf("envector: WithKeyPath required")
	}
	if !KeysExist(opts...) {
		return nil, ErrKeysNotFound
	}
	encBytes, err := os.ReadFile(filepath.Join(o.Path, encKeyFile))
	if err != nil {
		return nil, fmt.Errorf("envector: read %s: %w", encKeyFile, err)
	}
	evalBytes, err := os.ReadFile(filepath.Join(o.Path, evalKeyFile))
	if err != nil {
		return nil, fmt.Errorf("envector: read %s: %w", evalKeyFile, err)
	}
	secBytes, err := os.ReadFile(filepath.Join(o.Path, secKeyFile))
	if err != nil {
		return nil, fmt.Errorf("envector: read %s: %w", secKeyFile, err)
	}

	p := crypto.Default()
	ckks, err := p.NewCKKSContext(crypto.CKKSParams{
		Preset:   o.Preset,
		DimList:  []int{o.Dim},
		EvalMode: o.EvalMode,
	})
	if err != nil {
		return nil, fmt.Errorf("envector: new ckks context: %w", err)
	}
	enc, err := p.NewEncryptor(ckks, encBytes)
	if err != nil {
		_ = ckks.Close()
		return nil, fmt.Errorf("envector: new encryptor: %w", err)
	}
	dec, err := p.NewDecryptor(ckks, secBytes)
	if err != nil {
		_ = enc.Close()
		_ = ckks.Close()
		return nil, fmt.Errorf("envector: new decryptor: %w", err)
	}

	return &Keys{
		id:           o.KeyID,
		ckks:         ckks,
		enc:          enc,
		dec:          dec,
		evalKeyBytes: evalBytes,
	}, nil
}
