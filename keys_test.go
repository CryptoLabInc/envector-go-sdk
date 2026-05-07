package envector

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/CryptoLabInc/envector-go-sdk/internal/crypto"
)

func baseKeyOpts(dir string) []KeysOption {
	return []KeysOption{
		WithKeyPath(dir),
		WithKeyID("test-key"),
		WithKeyPreset(PresetIP0),
		WithKeyEvalMode(EvalModeRMP),
		WithKeyDim(128),
	}
}

func TestKeysExist_FalseWhenEmpty(t *testing.T) {
	if KeysExist(baseKeyOpts(t.TempDir())...) {
		t.Error("expected false on empty dir")
	}
	if KeysExist() {
		t.Error("expected false when Path unset")
	}
}

func TestGenerateKeys_CreatesAllThreeFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := GenerateKeys(baseKeyOpts(dir)...); err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	if !KeysExist(baseKeyOpts(dir)...) {
		t.Error("KeysExist still false after generate")
	}
	// pyenvector 1.2.2 parity: only the .json envelopes are kept; the raw
	// .bin temporaries libevi emits are wrapped-then-deleted.
	for _, name := range []string{encKeyJSONFile, evalKeyJSONFile, secKeyJSONFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing: %v", name, err)
		}
	}
	for _, name := range []string{encKeyBinFile, evalKeyBinFile, secKeyBinFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s must be cleaned up after wrap, got err=%v", name, err)
		}
	}
}

func TestGenerateKeys_RefusesOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := GenerateKeys(baseKeyOpts(dir)...); err != nil {
		t.Fatalf("first GenerateKeys: %v", err)
	}
	if err := GenerateKeys(baseKeyOpts(dir)...); !errors.Is(err, ErrKeysAlreadyExist) {
		t.Errorf("second GenerateKeys: got %v, want ErrKeysAlreadyExist", err)
	}
}

func TestGenerateKeys_RequiresPath(t *testing.T) {
	if err := GenerateKeys(WithKeyID("k"), WithKeyDim(4)); err == nil {
		t.Error("expected error when WithKeyPath absent")
	}
}

func TestGenerateKeys_RequiresKeyID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := GenerateKeys(WithKeyPath(dir), WithKeyDim(4)); err == nil {
		t.Error("expected error when WithKeyID absent")
	}
}

func TestGenerateKeys_RequiresDim(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := GenerateKeys(WithKeyPath(dir), WithKeyID("k")); err == nil {
		t.Error("expected error when WithKeyDim absent (dim=0)")
	}
}

func TestOpenKeysFromFile_RequiresKeyID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	_ = GenerateKeys(baseKeyOpts(dir)...) // seed files so path check passes
	if _, err := OpenKeysFromFile(WithKeyPath(dir), WithKeyDim(128)); err == nil {
		t.Error("expected error when WithKeyID absent")
	}
}

func TestOpenKeysFromFile_MissingReturnsErrKeysNotFound(t *testing.T) {
	_, err := OpenKeysFromFile(baseKeyOpts(t.TempDir())...)
	if !errors.Is(err, ErrKeysNotFound) {
		t.Errorf("got %v, want ErrKeysNotFound", err)
	}
}

func TestOpenKeysFromFile_HappyPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := GenerateKeys(baseKeyOpts(dir)...); err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	keys, err := OpenKeysFromFile(baseKeyOpts(dir)...)
	if err != nil {
		t.Fatalf("OpenKeysFromFile: %v", err)
	}
	defer keys.Close()

	if keys.ID() != "test-key" {
		t.Errorf("ID() = %q, want %q", keys.ID(), "test-key")
	}
	if len(keys.evalKeyBytes) == 0 {
		t.Error("evalKeyBytes not loaded")
	}
}

func TestKeys_EncryptProducesDistinctCiphertexts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	_ = GenerateKeys(baseKeyOpts(dir)...)
	keys, err := OpenKeysFromFile(baseKeyOpts(dir)...)
	if err != nil {
		t.Fatalf("OpenKeysFromFile: %v", err)
	}
	defer keys.Close()

	vec1 := make([]float32, 128)
	vec2 := make([]float32, 128)
	for i := range vec1 {
		vec1[i] = float32(i) / 128
		vec2[i] = float32(128-i) / 128
	}
	ciphers, innerCounts, err := keys.Encrypt([][]float32{vec1, vec2})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ciphers) != len(innerCounts) {
		t.Fatalf("ciphers/innerCounts length mismatch: %d vs %d", len(ciphers), len(innerCounts))
	}
	var total int
	for _, c := range innerCounts {
		total += c
	}
	if total != 2 {
		t.Fatalf("sum(innerCounts) = %d, want 2 (logical input count)", total)
	}
	for i, b := range ciphers {
		if len(b) == 0 {
			t.Fatalf("ciphertext %d is empty", i)
		}
	}
	// Distinct plaintext inputs must not collapse into a byte-identical
	// ciphertext. When libevi keeps them in separate ciphers we compare
	// those directly; when it slot-packs them into one cipher, the
	// distinctness claim collapses to "the packed cipher is non-empty",
	// already asserted above.
	if len(ciphers) >= 2 && bytes.Equal(ciphers[0], ciphers[1]) {
		t.Error("distinct vectors must yield distinct ciphertexts")
	}
	// Decrypt round trip is exercised end-to-end against a real server in
	// integration tests; the cgo decryptor only accepts evi_search_result
	// payloads produced by the server, which the SDK cannot synthesise here.
}

func TestKeys_AfterClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	_ = GenerateKeys(baseKeyOpts(dir)...)
	keys, _ := OpenKeysFromFile(baseKeyOpts(dir)...)
	_ = keys.Close()

	if _, _, err := keys.Encrypt([][]float32{{1}}); !errors.Is(err, ErrKeysNotForEncrypt) {
		t.Errorf("Encrypt after Close: got %v, want ErrKeysNotForEncrypt", err)
	}
	if _, _, err := keys.Decrypt(nil); !errors.Is(err, ErrKeysNotForDecrypt) {
		t.Errorf("Decrypt after Close: got %v, want ErrKeysNotForDecrypt", err)
	}
	// Second Close must not panic.
	if err := keys.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestOpenKeysFromFile_PartsEnc_NoEvalNoSec(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := GenerateKeys(baseKeyOpts(dir)...); err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	keys, err := OpenKeysFromFile(append(baseKeyOpts(dir), WithKeyParts(KeyPartEnc))...)
	if err != nil {
		t.Fatalf("OpenKeysFromFile: %v", err)
	}
	defer keys.Close()

	if keys.enc == nil {
		t.Error("encryptor must be loaded for KeyPartEnc")
	}
	if keys.dec != nil {
		t.Error("decryptor must not be loaded without KeyPartSec")
	}
	if keys.evalKeyBytes != nil {
		t.Error("evalKeyBytes must not be loaded without KeyPartEval")
	}

	if _, _, err := keys.Decrypt(nil); !errors.Is(err, ErrKeysNotForDecrypt) {
		t.Errorf("Decrypt without KeyPartSec: got %v, want ErrKeysNotForDecrypt", err)
	}
}

func TestOpenKeysFromFile_PartsEncEval_ClientSide(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := GenerateKeys(baseKeyOpts(dir)...); err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	keys, err := OpenKeysFromFile(append(baseKeyOpts(dir), WithKeyParts(KeyPartEnc, KeyPartEval))...)
	if err != nil {
		t.Fatalf("OpenKeysFromFile: %v", err)
	}
	defer keys.Close()

	if keys.enc == nil {
		t.Error("encryptor must be loaded for KeyPartEnc")
	}
	if keys.dec != nil {
		t.Error("decryptor must not be loaded without KeyPartSec")
	}
	if len(keys.evalKeyBytes) == 0 {
		t.Error("evalKeyBytes must be loaded for KeyPartEval")
	}
}

func TestOpenKeysFromFile_PartsSec_VaultSide(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := GenerateKeys(baseKeyOpts(dir)...); err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	keys, err := OpenKeysFromFile(append(baseKeyOpts(dir), WithKeyParts(KeyPartSec))...)
	if err != nil {
		t.Fatalf("OpenKeysFromFile: %v", err)
	}
	defer keys.Close()

	if keys.dec == nil {
		t.Error("decryptor must be loaded for KeyPartSec")
	}
	if keys.enc != nil {
		t.Error("encryptor must not be loaded without KeyPartEnc")
	}
	if keys.evalKeyBytes != nil {
		t.Error("evalKeyBytes must not be loaded without KeyPartEval")
	}

	if _, _, err := keys.Encrypt([][]float32{{1, 2}}); !errors.Is(err, ErrKeysNotForEncrypt) {
		t.Errorf("Encrypt without KeyPartEnc: got %v, want ErrKeysNotForEncrypt", err)
	}
}

// TestOpenKeysFromFile_LegacyBinBundle exercises the reverse-compat path:
// a directory holding only the raw .bin trio (e.g. bundles produced by an
// older Go SDK release that predated the JSON envelope, or manually-unwrapped
// pyenvector keys) must still open.
func TestOpenKeysFromFile_LegacyBinBundle(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "json-src")
	if err := GenerateKeys(baseKeyOpts(srcDir)...); err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}

	binDir := filepath.Join(t.TempDir(), "bin-only")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	unwraps := []struct {
		in, out string
		fn      func(string, string) error
	}{
		{filepath.Join(srcDir, encKeyJSONFile), filepath.Join(binDir, encKeyBinFile), crypto.UnwrapEncKey},
		{filepath.Join(srcDir, evalKeyJSONFile), filepath.Join(binDir, evalKeyBinFile), crypto.UnwrapEvalKey},
		{filepath.Join(srcDir, secKeyJSONFile), filepath.Join(binDir, secKeyBinFile), crypto.UnwrapSecKey},
	}
	for _, u := range unwraps {
		if err := u.fn(u.in, u.out); err != nil {
			t.Fatalf("unwrap %s: %v", u.in, err)
		}
	}

	if !KeysExist(baseKeyOpts(binDir)...) {
		t.Fatal("KeysExist must accept a .bin-only bundle")
	}
	keys, err := OpenKeysFromFile(baseKeyOpts(binDir)...)
	if err != nil {
		t.Fatalf("OpenKeysFromFile (.bin): %v", err)
	}
	defer keys.Close()

	vec := make([]float32, 128)
	for i := range vec {
		vec[i] = float32(i) / 128
	}
	if _, _, err := keys.Encrypt([][]float32{vec}); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
}

func TestRegisterKeys_WithoutEvalPart_ReturnsErr(t *testing.T) {
	c, _ := newFakeClient(t)
	dir := filepath.Join(t.TempDir(), "keys")
	if err := GenerateKeys(baseKeyOpts(dir)...); err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	keys, err := OpenKeysFromFile(append(baseKeyOpts(dir), WithKeyParts(KeyPartSec))...)
	if err != nil {
		t.Fatalf("OpenKeysFromFile: %v", err)
	}
	defer keys.Close()

	if err := c.RegisterKeys(context.Background(), keys); !errors.Is(err, ErrKeysNotForRegister) {
		t.Errorf("RegisterKeys without KeyPartEval: got %v, want ErrKeysNotForRegister", err)
	}
	if err := c.ActivateKeys(context.Background(), keys); !errors.Is(err, ErrKeysNotForRegister) {
		t.Errorf("ActivateKeys without KeyPartEval: got %v, want ErrKeysNotForRegister", err)
	}
}

// TestKeysExist_PartsAware exercises the KeyParts-aware lookup. Vault's
// agent-manifest delivery only ships EncKey to the client (Eval/Sec stay
// in Vault), so the consumer opens that directory with
// WithKeyParts(KeyPartEnc) and expects KeysExist to return true on an
// Enc-only directory. The previous implementation walked all three slots
// unconditionally and rejected the bundle.
func TestKeysExist_PartsAware(t *testing.T) {
	encOnly := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, encKeyJSONFile), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("enc-only dir + WithKeyParts(KeyPartEnc) → true", func(t *testing.T) {
		dir := encOnly(t)
		opts := append(baseKeyOpts(dir), WithKeyParts(KeyPartEnc))
		if !KeysExist(opts...) {
			t.Error("KeysExist with KeyPartEnc must accept Enc-only directory")
		}
	})

	t.Run("enc-only dir + default parts (= all three) → false", func(t *testing.T) {
		dir := encOnly(t)
		// No WithKeyParts → resolveKeyParts treats it as all three required.
		if KeysExist(baseKeyOpts(dir)...) {
			t.Error("default parts must require all 3 slots")
		}
	})

	t.Run("enc-only dir + WithKeyParts(KeyPartEval) → false (eval missing)", func(t *testing.T) {
		dir := encOnly(t)
		opts := append(baseKeyOpts(dir), WithKeyParts(KeyPartEval))
		if KeysExist(opts...) {
			t.Error("requesting Eval on an Enc-only dir must fail")
		}
	})
}
