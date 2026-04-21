package envector

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/CryptoLabInc/envector-go-sdk/internal/crypto"
)

// Key bundle filenames. GenerateKeys writes the pyenvector 1.2.2-style
// JSON envelopes; the raw .bin forms are still recognised on open so
// legacy bundles (or bundles produced by the older Go SDK releases that
// skipped the JSON wrap) continue to load.
const (
	encKeyBinFile   = "EncKey.bin"
	evalKeyBinFile  = "EvalKey.bin"
	secKeyBinFile   = "SecKey.bin"
	encKeyJSONFile  = "EncKey.json"
	evalKeyJSONFile = "EvalKey.json"
	secKeyJSONFile  = "SecKey.json"
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

// Encrypt runs the local FHE encrypt stage. libevi packs input vectors via
// CKKS slot packing, so len(ciphers) can be smaller than len(vectors);
// innerCounts[i] reports how many logical input vectors are packed into
// ciphers[i] and sum(innerCounts) == len(vectors). Index.Insert uses that
// mapping to align server-side item allocation and metadata with logical
// vectors rather than ciphertexts. Returns ErrKeysNotForEncrypt when the
// bundle was opened without KeyPartEnc or has been Closed.
func (k *Keys) Encrypt(vectors [][]float32) (ciphers [][]byte, innerCounts []int, err error) {
	if k == nil || k.enc == nil {
		return nil, nil, ErrKeysNotForEncrypt
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

// resolveKeySlot returns the preferred source path for one of the three
// key slots, preferring the pyenvector-style .json envelope when both
// formats coexist in the directory.
func resolveKeySlot(dir, binName, jsonName string) (path string, isJSON bool, exists bool) {
	jsonPath := filepath.Join(dir, jsonName)
	if _, err := os.Stat(jsonPath); err == nil {
		return jsonPath, true, true
	}
	binPath := filepath.Join(dir, binName)
	if _, err := os.Stat(binPath); err == nil {
		return binPath, false, true
	}
	return "", false, false
}

// KeysExist reports whether the bundle (Enc/Eval/Sec) is present under
// WithKeyPath. Either the .json envelope (pyenvector 1.2.2 format) or the
// legacy .bin form satisfies each slot.
func KeysExist(opts ...KeysOption) bool {
	o := buildKeysOptions(opts)
	if o.Path == "" {
		return false
	}
	slots := [3][2]string{
		{encKeyBinFile, encKeyJSONFile},
		{evalKeyBinFile, evalKeyJSONFile},
		{secKeyBinFile, secKeyJSONFile},
	}
	for _, s := range slots {
		if _, _, ok := resolveKeySlot(o.Path, s[0], s[1]); !ok {
			return false
		}
	}
	return true
}

// GenerateKeys writes a fresh pyenvector-compatible bundle at WithKeyPath
// (three JSON envelopes: EncKey.json, EvalKey.json, SecKey.json). Returns
// ErrKeysAlreadyExist when any of the three slots — in either format —
// is already present; GenerateKeys never overwrites existing keys.
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
	if err := gen.Generate(); err != nil {
		return err
	}
	// libevi's MultiKeyGenerator emits the raw .bin trio; wrap each into
	// pyenvector's JSON envelope then drop the .bin so the on-disk shape
	// matches what `python -m pyenvector.cli.pyenvector_keygen` produces.
	steps := []struct {
		binFile  string
		jsonFile string
		wrap     func(keyID, binPath, jsonPath string) error
	}{
		{encKeyBinFile, encKeyJSONFile, crypto.WrapEncKey},
		{evalKeyBinFile, evalKeyJSONFile, crypto.WrapEvalKey},
		{secKeyBinFile, secKeyJSONFile, crypto.WrapSecKey},
	}
	for _, s := range steps {
		binPath := filepath.Join(o.Path, s.binFile)
		jsonPath := filepath.Join(o.Path, s.jsonFile)
		if err := s.wrap(o.KeyID, binPath, jsonPath); err != nil {
			return fmt.Errorf("envector: wrap %s: %w", s.binFile, err)
		}
		if err := os.Remove(binPath); err != nil {
			return fmt.Errorf("envector: remove %s: %w", s.binFile, err)
		}
	}
	return nil
}

// OpenKeysFromFile loads the bundle at WithKeyPath and builds the
// Encryptor + Decryptor pair backing a Keys handle. Accepts both the
// pyenvector-style JSON envelopes (default output of GenerateKeys) and
// legacy .bin files — per-slot format is detected automatically, so
// mix-and-match is fine. Returns ErrKeysNotFound when a required slot is
// absent in either format. WithKeyParts narrows the set of key materials
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

	// Stage the requested slots into a tempdir using canonical .bin names
	// so the path-based cgo loaders (evi_keypack_load_enc_key /
	// evi_secret_key_create_from_path) can find them regardless of whether
	// the source was .json or .bin. The tempdir is torn down once every
	// cgo handle has finished loading — libevi reads the files eagerly.
	stage, err := os.MkdirTemp("", "envector-keys-*")
	if err != nil {
		return nil, fmt.Errorf("envector: stage tempdir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(stage) }

	materialise := func(binName, jsonName string, unwrap func(jsonPath, binPath string) error) (string, error) {
		srcPath, isJSON, ok := resolveKeySlot(o.Path, binName, jsonName)
		if !ok {
			return "", ErrKeysNotFound
		}
		dstPath := filepath.Join(stage, binName)
		if isJSON {
			if err := unwrap(srcPath, dstPath); err != nil {
				return "", fmt.Errorf("envector: unwrap %s: %w", jsonName, err)
			}
			return dstPath, nil
		}
		if err := copyFile(srcPath, dstPath); err != nil {
			return "", fmt.Errorf("envector: stage %s: %w", binName, err)
		}
		return dstPath, nil
	}

	if wantEnc {
		if _, err := materialise(encKeyBinFile, encKeyJSONFile, crypto.UnwrapEncKey); err != nil {
			cleanup()
			return nil, err
		}
	}
	var evalBytes []byte
	if wantEval {
		path, err := materialise(evalKeyBinFile, evalKeyJSONFile, crypto.UnwrapEvalKey)
		if err != nil {
			cleanup()
			return nil, err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("envector: read %s: %w", evalKeyBinFile, err)
		}
		evalBytes = b
	}
	if wantSec {
		if _, err := materialise(secKeyBinFile, secKeyJSONFile, crypto.UnwrapSecKey); err != nil {
			cleanup()
			return nil, err
		}
	}

	p := crypto.Default()
	ckks, err := p.NewCKKSContext(crypto.CKKSParams{
		Preset:   o.Preset.String(),
		DimList:  []int{o.Dim},
		EvalMode: o.EvalMode.String(),
	})
	if err != nil {
		cleanup()
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
		enc, err := p.NewEncryptor(ckks, stage)
		if err != nil {
			_ = ckks.Close()
			cleanup()
			return nil, fmt.Errorf("envector: new encryptor: %w", err)
		}
		keys.enc = enc
	}
	if wantEval {
		keys.evalKeyBytes = evalBytes
	}
	if wantSec {
		dec, err := p.NewDecryptor(ckks, stage)
		if err != nil {
			if keys.enc != nil {
				_ = keys.enc.Close()
			}
			_ = ckks.Close()
			cleanup()
			return nil, fmt.Errorf("envector: new decryptor: %w", err)
		}
		keys.dec = dec
	}

	cleanup()
	return keys, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
