package envector

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CryptoLabInc/envector-go-sdk/internal/crypto"
)

const (
	encKeyFile  = "EncKey.bin"
	evalKeyFile = "EvalKey.bin"
	secKeyFile  = "SecKey.bin"
)

// Keys is the local side of a 3-file FHE key bundle (EncKey / EvalKey /
// SecKey). It wraps a shared CKKS context together with an Encryptor and
// Decryptor derived from the bundle; EvalKey bytes are retained for
// Client.RegisterKeys uploads.
type Keys struct {
	id           string
	preset       string
	evalMode     string
	dim          int
	ckks         crypto.CKKSContext
	enc          crypto.Encryptor
	dec          crypto.Decryptor
	evalKeyBytes []byte
}

// ID returns the key identifier carried by the bundle. The server uses
// this string in RegisterKeys / LoadKeys / UnloadKeys / DeleteKeys.
func (k *Keys) ID() string { return k.id }

// Dim returns the FHE slot dimension this bundle was generated for.
// Index.Insert and Index.Score validate caller-supplied vector lengths
// against this value when the Index is bound to a Keys handle.
func (k *Keys) Dim() int { return k.dim }

// Close releases the cgo encryptor/decryptor/context handles and the
// in-memory EvalKey buffer. Subsequent Encrypt/Decrypt/RegisterKeys calls
// return ErrKeysNotForEncrypt / ErrKeysNotForDecrypt / ErrKeysNotForRegister
// since the corresponding parts are no longer loaded. Close is idempotent.
func (k *Keys) Close() error {
	if k == nil {
		return nil
	}
	if k.enc != nil {
		_ = k.enc.Close()
		k.enc = nil
	}
	if k.dec != nil {
		_ = k.dec.Close()
		k.dec = nil
	}
	if k.ckks != nil {
		_ = k.ckks.Close()
		k.ckks = nil
	}
	k.evalKeyBytes = nil
	return nil
}

// Encrypt runs the local FHE encrypt stage and returns one serialized
// Query byte slice per input vector, ready for Index.Insert. Returns
// ErrKeysNotForEncrypt when the bundle was opened without KeyPartEnc or
// has been Closed.
func (k *Keys) Encrypt(vectors [][]float32) ([][]byte, error) {
	if k == nil || k.enc == nil {
		return nil, ErrKeysNotForEncrypt
	}
	return k.enc.EncryptMultiple(vectors, "item")
}

// Decrypt unpacks a CiphertextScore blob produced by Index.Score into
// per-slot score vectors and their matching shard indices. The call is
// local only; no Client is required. Returns ErrKeysNotForDecrypt when
// the bundle was opened without KeyPartSec or has been Closed.
func (k *Keys) Decrypt(blob []byte) (scores [][]float64, shardIdx []int32, err error) {
	if k == nil || k.dec == nil {
		return nil, nil, ErrKeysNotForDecrypt
	}
	return k.dec.DecryptScore(blob)
}

// KeysExist reports whether the 3-file bundle (EncKey.bin, EvalKey.bin,
// SecKey.bin) is present under WithKeyPath.
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
	if err := o.validate(); err != nil {
		return err
	}
	if KeysExist(opts...) {
		return ErrKeysAlreadyExist
	}
	gen, err := crypto.Default().NewKeyGenerator(crypto.KeyGenParams{
		CKKSParams: crypto.CKKSParams{
			Preset:   o.Preset.String(),
			DimList:  []int{o.Dim},
			EvalMode: o.EvalMode.String(),
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
// when the bundle is absent. WithKeyParts narrows the set of key materials
// that get materialised; omitting it loads all three.
func OpenKeysFromFile(opts ...KeysOption) (*Keys, error) {
	o := buildKeysOptions(opts)
	if err := o.validate(); err != nil {
		return nil, err
	}
	if !KeysExist(opts...) {
		return nil, ErrKeysNotFound
	}

	wantEnc, wantEval, wantSec := resolveKeyParts(o.Parts)

	p := crypto.Default()
	ckks, err := p.NewCKKSContext(crypto.CKKSParams{
		Preset:   o.Preset.String(),
		DimList:  []int{o.Dim},
		EvalMode: o.EvalMode.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("envector: new ckks context: %w", err)
	}

	keys := &Keys{
		id:       o.KeyID,
		preset:   o.Preset.String(),
		evalMode: o.EvalMode.String(),
		dim:      o.Dim,
		ckks:     ckks,
	}

	if wantEnc {
		// Encryptor loads EncKey directly from o.Path via the provider
		// (upstream C API only accepts path-based loaders).
		enc, err := p.NewEncryptor(ckks, o.Path)
		if err != nil {
			_ = ckks.Close()
			return nil, fmt.Errorf("envector: new encryptor: %w", err)
		}
		keys.enc = enc
	}

	if wantEval {
		// EvalKey bytes are carried in-memory for Client.RegisterKeys
		// uploads only — the cgo Encryptor never touches them.
		evalBytes, err := os.ReadFile(filepath.Join(o.Path, evalKeyFile))
		if err != nil {
			if keys.enc != nil {
				_ = keys.enc.Close()
			}
			_ = ckks.Close()
			return nil, fmt.Errorf("envector: read %s: %w", evalKeyFile, err)
		}
		keys.evalKeyBytes = evalBytes
	}

	if wantSec {
		dec, err := p.NewDecryptor(ckks, o.Path)
		if err != nil {
			if keys.enc != nil {
				_ = keys.enc.Close()
			}
			_ = ckks.Close()
			return nil, fmt.Errorf("envector: new decryptor: %w", err)
		}
		keys.dec = dec
	}

	return keys, nil
}
