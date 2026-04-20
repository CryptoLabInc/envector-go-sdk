//go:build !libevi

package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	es2pb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2"
)

func TestMockProvider_EncryptDeterministic(t *testing.T) {
	p := Default()
	ctx, err := p.NewCKKSContext(CKKSParams{Preset: "FGb", DimList: []int{4}, EvalMode: "ip"})
	if err != nil {
		t.Fatalf("NewCKKSContext: %v", err)
	}
	defer ctx.Close()

	enc1, _ := p.NewEncryptor(ctx, []byte("encKey"))
	enc2, _ := p.NewEncryptor(ctx, []byte("encKey"))
	vec := [][]float32{{1, 2, 3, 4}, {5, 6, 7, 8}}

	a, err := enc1.EncryptMultiple(vec, "item")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := enc2.EncryptMultiple(vec, "item")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(a) != 2 || len(a) != len(b) {
		t.Fatalf("length mismatch: a=%d b=%d", len(a), len(b))
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			t.Errorf("vector %d not deterministic", i)
		}
	}
	// Different encodeType must change the prefix.
	c, _ := enc1.EncryptMultiple(vec, "query")
	if bytes.Equal(a[0], c[0]) {
		t.Error("encodeType not mixed into prefix")
	}
}

func TestMockProvider_DecryptScoreRoundTrip(t *testing.T) {
	p := Default()
	ctx, _ := p.NewCKKSContext(CKKSParams{Preset: "FGb", DimList: []int{4}, EvalMode: "ip"})
	defer ctx.Close()
	dec, _ := p.NewDecryptor(ctx, []byte("secKey"))

	buf, err := proto.Marshal(&es2pb.CiphertextScore{
		Id:       "q-1",
		ShardIdx: []uint64{0, 3, 7},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	scores, idx, err := dec.DecryptScore(buf)
	if err != nil {
		t.Fatalf("DecryptScore: %v", err)
	}
	if len(scores) != 3 || len(idx) != 3 {
		t.Fatalf("shape: scores=%d idx=%d", len(scores), len(idx))
	}
	if idx[0] != 0 || idx[1] != 3 || idx[2] != 7 {
		t.Errorf("shard idx not echoed: %v", idx)
	}
	if scores[1][0] != 3 {
		t.Errorf("score mirror broken: %v", scores[1])
	}
}

func TestMockProvider_KeyGenerator_WritesThreeFiles(t *testing.T) {
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "vault")
	gen, err := Default().NewKeyGenerator(KeyGenParams{
		CKKSParams: CKKSParams{Preset: "FGb", DimList: []int{8}, EvalMode: "ip"},
		KeyPath:    keyDir,
		KeyID:      "vault-key",
	})
	if err != nil {
		t.Fatalf("NewKeyGenerator: %v", err)
	}
	if err := gen.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, name := range []string{"EncKey.json", "EvalKey.json", "SecKey.json"} {
		path := filepath.Join(keyDir, name)
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Errorf("%s missing or empty: %v", name, err)
		}
	}
}
