//go:build !libevi

package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/proto"

	es2pb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2"
)

func defaultProvider() Provider { return mockProvider{} }

type mockProvider struct{}

type mockContext struct{ params CKKSParams }

func (*mockContext) Close() error { return nil }

func (mockProvider) NewCKKSContext(p CKKSParams) (CKKSContext, error) {
	return &mockContext{params: p}, nil
}

type mockEncryptor struct {
	ctx    *mockContext
	encKey []byte
}

func (*mockEncryptor) Close() error { return nil }

func (m *mockEncryptor) EncryptMultiple(vectors [][]float32, encodeType string) ([][]byte, error) {
	out := make([][]byte, len(vectors))
	for i, vec := range vectors {
		buf := make([]byte, 4*len(vec))
		for j, f := range vec {
			binary.LittleEndian.PutUint32(buf[4*j:], math.Float32bits(f))
		}
		h := sha256.New()
		h.Write([]byte(encodeType))
		h.Write(m.encKey)
		h.Write(buf)
		out[i] = append(h.Sum(nil), buf...)
	}
	return out, nil
}

func (mockProvider) NewEncryptor(ctx CKKSContext, encKey []byte) (Encryptor, error) {
	mc, _ := ctx.(*mockContext)
	dup := append([]byte(nil), encKey...)
	return &mockEncryptor{ctx: mc, encKey: dup}, nil
}

type mockDecryptor struct {
	ctx    *mockContext
	secKey []byte
}

func (*mockDecryptor) Close() error { return nil }

func (m *mockDecryptor) DecryptScore(scoreBytes []byte) ([][]float64, []int32, error) {
	var score es2pb.CiphertextScore
	if err := proto.Unmarshal(scoreBytes, &score); err != nil {
		return nil, nil, err
	}
	shards := score.GetShardIdx()
	out := make([][]float64, len(shards))
	idx := make([]int32, len(shards))
	for i, s := range shards {
		idx[i] = int32(s)
		out[i] = []float64{float64(s)}
	}
	return out, idx, nil
}

func (mockProvider) NewDecryptor(ctx CKKSContext, secKey []byte) (Decryptor, error) {
	mc, _ := ctx.(*mockContext)
	dup := append([]byte(nil), secKey...)
	return &mockDecryptor{ctx: mc, secKey: dup}, nil
}

type mockKeyGen struct{ params KeyGenParams }

func (m *mockKeyGen) Generate() error {
	if err := os.MkdirAll(m.params.KeyPath, 0o755); err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"key_id":    m.params.KeyID,
		"preset":    m.params.Preset,
		"eval_mode": m.params.EvalMode,
		"dim_list":  m.params.DimList,
	})
	if err != nil {
		return err
	}
	for _, name := range []string{"EncKey.json", "EvalKey.json", "SecKey.json"} {
		path := filepath.Join(m.params.KeyPath, name)
		if err := os.WriteFile(path, payload, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func (mockProvider) NewKeyGenerator(p KeyGenParams) (KeyGenerator, error) {
	return &mockKeyGen{params: p}, nil
}
