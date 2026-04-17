package envector

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	es2pb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2"
)

func baseKeyOpts(dir string) []KeysOption {
	return []KeysOption{
		WithKeyPath(dir),
		WithKeyID("test-key"),
		WithKeyPreset("FGb"),
		WithKeyEvalMode("ip"),
		WithKeyDim(4),
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
	for _, name := range []string{encKeyFile, evalKeyFile, secKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing: %v", name, err)
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

func TestKeys_EncryptDecryptRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	_ = GenerateKeys(baseKeyOpts(dir)...)
	keys, err := OpenKeysFromFile(baseKeyOpts(dir)...)
	if err != nil {
		t.Fatalf("OpenKeysFromFile: %v", err)
	}
	defer keys.Close()

	vecs := [][]float32{{1, 2, 3, 4}, {5, 6, 7, 8}}
	ciphers, err := keys.Encrypt(vecs)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ciphers) != 2 {
		t.Fatalf("got %d ciphers, want 2", len(ciphers))
	}
	if bytes.Equal(ciphers[0], ciphers[1]) {
		t.Error("distinct vectors must yield distinct ciphertexts")
	}

	// Mock decryptor mirrors ShardIdx into scores.
	buf, _ := proto.Marshal(&es2pb.CiphertextScore{ShardIdx: []uint64{2, 5}})
	scores, idx, err := keys.Decrypt(buf)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(scores) != 2 || idx[1] != 5 {
		t.Errorf("Decrypt shape wrong: scores=%v idx=%v", scores, idx)
	}
}

func TestKeys_AfterClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	_ = GenerateKeys(baseKeyOpts(dir)...)
	keys, _ := OpenKeysFromFile(baseKeyOpts(dir)...)
	_ = keys.Close()

	if _, err := keys.Encrypt([][]float32{{1}}); !errors.Is(err, ErrKeysClosed) {
		t.Errorf("Encrypt after Close: got %v, want ErrKeysClosed", err)
	}
	if _, _, err := keys.Decrypt(nil); !errors.Is(err, ErrKeysClosed) {
		t.Errorf("Decrypt after Close: got %v, want ErrKeysClosed", err)
	}
	// Second Close must not panic.
	if err := keys.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
