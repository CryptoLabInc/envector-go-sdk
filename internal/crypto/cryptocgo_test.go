package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCGO_ContextRoundTrip(t *testing.T) {
	p := Default()
	for i := 0; i < 5; i++ {
		ctx, err := p.NewCKKSContext(CKKSParams{
			Preset:   "ip",
			DimList:  []int{128},
			EvalMode: "rmp",
		})
		if err != nil {
			t.Fatalf("iter %d NewCKKSContext: %v", i, err)
		}
		if err := ctx.Close(); err != nil {
			t.Fatalf("iter %d Close: %v", i, err)
		}
	}
}

func TestCGO_Preset_Invalid(t *testing.T) {
	_, err := Default().NewCKKSContext(CKKSParams{
		Preset:   "qf0", // QF disabled in the active set
		DimList:  []int{128},
		EvalMode: "rmp",
	})
	if err == nil {
		t.Fatal("expected error for qf0 preset")
	}
}

func TestCGO_KeyGen_WritesBinFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	gen, err := Default().NewKeyGenerator(KeyGenParams{
		CKKSParams: CKKSParams{
			Preset:   "ip",
			DimList:  []int{128},
			EvalMode: "rmp",
		},
		KeyPath: dir,
		KeyID:   "smoke",
	})
	if err != nil {
		t.Fatalf("NewKeyGenerator: %v", err)
	}
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, name := range []string{cgoEncKeyFile, cgoEvalKeyFile, cgoSecKeyFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s missing: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}

// TestCGO_Encrypt_BulkReturnsNonEmpty generates a key set, opens an
// Encryptor against it, and verifies that EncryptMultiple produces a
// non-empty serialized query per returned ciphertext and a parallel
// innerCounts slice whose sum matches the logical input vector count
// (libevi may pack multiple input vectors into a single ciphertext via
// CKKS slot packing, so len(out) can be < len(input)).
func TestCGO_Encrypt_BulkReturnsNonEmpty(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	p := Default()
	gen, err := p.NewKeyGenerator(KeyGenParams{
		CKKSParams: CKKSParams{Preset: "ip", DimList: []int{128}, EvalMode: "rmp"},
		KeyPath:    dir,
		KeyID:      "enc-smoke",
	})
	if err != nil {
		t.Fatalf("NewKeyGenerator: %v", err)
	}
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	ctx, err := p.NewCKKSContext(CKKSParams{Preset: "ip", DimList: []int{128}, EvalMode: "rmp"})
	if err != nil {
		t.Fatalf("NewCKKSContext: %v", err)
	}
	defer ctx.Close()

	enc, err := p.NewEncryptor(ctx, dir)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	defer enc.Close()

	vec := make([]float32, 128)
	for i := range vec {
		vec[i] = float32(i) / 128.0
	}
	const wantInputs = 2
	out, innerCounts, err := enc.EncryptMultiple([][]float32{vec, vec}, "item")
	if err != nil {
		t.Fatalf("EncryptMultiple: %v", err)
	}
	if len(out) != len(innerCounts) {
		t.Fatalf("ciphers/innerCounts length mismatch: %d vs %d", len(out), len(innerCounts))
	}
	for i, b := range out {
		if len(b) == 0 {
			t.Errorf("ciphertext %d is empty", i)
		}
	}
	var totalItems int
	for _, c := range innerCounts {
		totalItems += c
	}
	if totalItems != wantInputs {
		t.Fatalf("sum(innerCounts) = %d, want %d (logical input count)", totalItems, wantInputs)
	}
}

func TestCGO_Decryptor_OpenAgainstGeneratedKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	p := Default()
	gen, _ := p.NewKeyGenerator(KeyGenParams{
		CKKSParams: CKKSParams{Preset: "ip", DimList: []int{128}, EvalMode: "rmp"},
		KeyPath:    dir,
		KeyID:      "dec-smoke",
	})
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	ctx, err := p.NewCKKSContext(CKKSParams{Preset: "ip", DimList: []int{128}, EvalMode: "rmp"})
	if err != nil {
		t.Fatalf("NewCKKSContext: %v", err)
	}
	defer ctx.Close()

	dec, err := p.NewDecryptor(ctx, dir)
	if err != nil {
		t.Fatalf("NewDecryptor: %v", err)
	}
	if err := dec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
