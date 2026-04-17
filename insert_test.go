package envector

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestIndex_Insert_RequiresKeys(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.indexList = []string{"rune"}

	idx, _ := c.Index(context.Background(), WithIndexName("rune"))
	_, err := idx.Insert(context.Background(), InsertRequest{Vectors: [][]float32{{1, 2}}})
	if !errors.Is(err, ErrKeysRequired) {
		t.Errorf("got %v, want ErrKeysRequired", err)
	}
}

func TestIndex_Insert_EmptyVectorsShortCircuit(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.indexList = []string{"rune"}
	keys := openTestKeys(t)

	idx, _ := c.Index(context.Background(),
		WithIndexName("rune"),
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
	fake.indexList = []string{"rune"}
	fake.itemIDs = []int64{101, 102}
	keys := openTestKeys(t)

	idx, _ := c.Index(context.Background(),
		WithIndexName("rune"),
		WithIndexKeys(keys),
	)
	req := InsertRequest{
		Vectors:  [][]float32{{1, 2, 3, 4}, {5, 6, 7, 8}},
		Metadata: []string{`{"a":"x"}`, `{"a":"y"}`},
	}
	res, err := idx.Insert(context.Background(), req)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if !reflect.DeepEqual(res.ItemIDs, []int64{101, 102}) {
		t.Errorf("ItemIDs = %v", res.ItemIDs)
	}
	if fake.batchInsertIndex != "rune" {
		t.Errorf("IndexName = %q", fake.batchInsertIndex)
	}

	var allPacked []string
	for _, frame := range fake.batchInsertPackets {
		for _, pv := range frame {
			if pv.GetVector().GetCipherVector() == nil {
				t.Error("PackedVectors missing cipher_vector")
			}
			if md := pv.GetMetadata(); len(md) == 1 {
				allPacked = append(allPacked, md[0])
			}
		}
	}
	want := []string{`{"a":"x"}`, `{"a":"y"}`}
	if !reflect.DeepEqual(allPacked, want) {
		t.Errorf("metadata order = %v, want %v", allPacked, want)
	}
}

func TestIndex_Insert_ChunksAboveThreshold(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.indexList = []string{"rune"}
	keys := openTestKeys(t)
	// Mock encrypt output is ~32 + 4*dim bytes per vector. To exceed the
	// 1 MiB frame cutoff we fake many small vectors; mock provider keeps
	// these deterministic.
	n := 200
	dim := 2000 // per-vector ~8032 bytes -> 200 vecs ~ 1.6 MiB total
	vecs := make([][]float32, n)
	for i := range vecs {
		vecs[i] = make([]float32, dim)
	}

	idx, _ := c.Index(context.Background(),
		WithIndexName("rune"),
		WithIndexKeys(keys),
	)
	if _, err := idx.Insert(context.Background(), InsertRequest{Vectors: vecs}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	if len(fake.batchInsertPackets) < 2 {
		t.Errorf("expected >=2 stream frames to cross 1 MiB, got %d", len(fake.batchInsertPackets))
	}
}
