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

type Keys struct {
	id           string
	ckks         crypto.CKKSContext
	enc          crypto.Encryptor
	dec          crypto.Decryptor
	evalKeyBytes []byte
	closed       bool
	activated    *Client
}

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

func (k *Keys) Encrypt(vectors [][]float32) ([][]byte, error) {
	if k == nil || k.closed {
		return nil, ErrKeysClosed
	}
	return k.enc.EncryptMultiple(vectors, "item")
}

func (k *Keys) Decrypt(blob []byte) (scores [][]float64, shardIdx []int32, err error) {
	if k == nil || k.closed {
		return nil, nil, ErrKeysClosed
	}
	return k.dec.DecryptScore(blob)
}

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
