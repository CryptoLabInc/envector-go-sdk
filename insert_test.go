package envector

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestIndex_Insert_RequiresKeys(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.indexList = []string{"demo"}

	idx, _ := c.Index(context.Background(), WithIndexName("demo"))
	_, err := idx.Insert(context.Background(), InsertRequest{Vectors: [][]float32{{1, 2}}})
	if !errors.Is(err, ErrKeysRequired) {
		t.Errorf("got %v, want ErrKeysRequired", err)
	}
}

func TestIndex_Insert_EmptyVectorsShortCircuit(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.indexList = []string{"demo"}
	keys := openTestKeys(t)

	idx, _ := c.Index(context.Background(),
		WithIndexName("demo"),
		WithIndexKeys(keys),
	)
	res, err := idx.Insert(context.Background(), InsertRequest{})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if len(res.ItemIDs) != 0 {
		t.Errorf("ItemIDs = %v", res.ItemIDs)
	}
	if len(fake.batchInsertPackets) != 0 {
		t.Error("no RPC should have been sent")
	}
}

func TestIndex_Insert_StreamsPackedVectorsAndPassesMetadata(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.indexList = []string{"demo"}
	fake.itemIDs = []int64{101, 102}
	keys := openTestKeys(t)

	idx, _ := c.Index(context.Background(),
		WithIndexName("demo"),
		WithIndexKeys(keys),
	)
	vec1 := make([]float32, 128)
	vec2 := make([]float32, 128)
	for i := range vec1 {
		vec1[i] = float32(i)
		vec2[i] = float32(2 * i)
	}
	req := InsertRequest{
		Vectors:  [][]float32{vec1, vec2},
		Metadata: []string{`{"a":"x"}`, `{"a":"y"}`},
	}
	res, err := idx.Insert(context.Background(), req)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if !reflect.DeepEqual(res.ItemIDs, []int64{101, 102}) {
		t.Errorf("ItemIDs = %v", res.ItemIDs)
	}
	if fake.batchInsertIndex != "demo" {
		t.Errorf("IndexName = %q", fake.batchInsertIndex)
	}

	// Flatten metadata across all packed ciphers — when libevi slot-packs
	// multiple input vectors into one ciphertext, SDK emits one metadata
	// entry per logical vector (count = innerItemCount, padded with ""
	// beyond the caller's flat array). Comparing the flattened head to the
	// caller's input preserves order regardless of packing decisions.
	var allPacked []string
	for _, frame := range fake.batchInsertPackets {
		for _, pv := range frame {
			if pv.GetVector().GetCipherVector() == nil {
				t.Error("PackedVectors missing cipher_vector")
			}
			allPacked = append(allPacked, pv.GetMetadata()...)
		}
	}
	want := []string{`{"a":"x"}`, `{"a":"y"}`}
	if len(allPacked) < len(want) {
		t.Fatalf("flattened metadata len %d < want %d", len(allPacked), len(want))
	}
	if !reflect.DeepEqual(allPacked[:len(want)], want) {
		t.Errorf("metadata order = %v, want leading %v", allPacked, want)
	}
}

func TestIndex_Insert_ChunksAboveThreshold(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.indexList = []string{"demo"}
	keys := openTestKeys(t)
	// Real libevi ciphertexts at preset IP / dim 128 are several hundred KB
	// each; 16 vectors comfortably crosses the 1 MiB frame cutoff and the
	// stream must split into >=2 BatchInsertData frames.
	n := 16
	dim := 128
	vecs := make([][]float32, n)
	for i := range vecs {
		vecs[i] = make([]float32, dim)
		for j := range vecs[i] {
			vecs[i][j] = float32(i*dim+j) / float32(n*dim)
		}
	}

	idx, _ := c.Index(context.Background(),
		WithIndexName("demo"),
		WithIndexKeys(keys),
	)
	if _, err := idx.Insert(context.Background(), InsertRequest{Vectors: vecs}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	if len(fake.batchInsertPackets) < 2 {
		t.Errorf("expected >=2 stream frames to cross 1 MiB, got %d", len(fake.batchInsertPackets))
	}
}
