//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"

	envector "github.com/CryptoLabInc/envector-go-sdk"
)

// TestCapture_SmallBatch (E1) — small Insert round-trips. The server
// allocates item IDs at slot-capacity granularity (libevi pads ciphertexts
// up to the CKKS packing width), so `len(ItemIDs) >= len(vectors)` is the
// meaningful contract rather than strict equality.
func TestCapture_SmallBatch(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()
	keys := newTestKeys(t, 128, envector.PresetIP0, envector.EvalModeRMP)
	idx := newTestIndex(t, ctx, client, keys)

	const n = 8
	vecs := sampleVectors(n, 128)
	md := make([]string, n)
	for i := range md {
		md[i] = fmt.Sprintf(`{"i":%d}`, i)
	}

	res, err := idx.Insert(ctx, envector.InsertRequest{
		Vectors:  vecs,
		Metadata: md,
	})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if len(res.ItemIDs) < n {
		t.Fatalf("ItemIDs count: got %d, want >= %d (logical vectors)", len(res.ItemIDs), n)
	}
	t.Logf("server allocated %d ItemIDs for %d logical vectors (slot-aligned)", len(res.ItemIDs), n)
}

// TestCapture_LargeBatch (E2) — enough ciphertexts to cross the 1 MiB
// frame cap in insert.go:11, verifying the server reassembles multi-frame
// streams into a single batch response. Same slot-alignment contract as
// E1 applies: the floor is `>= len(vectors)`, not equality.
func TestCapture_LargeBatch(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()
	keys := newTestKeys(t, 128, envector.PresetIP0, envector.EvalModeRMP)
	idx := newTestIndex(t, ctx, client, keys)

	const n = 128
	vecs := sampleVectors(n, 128)
	md := make([]string, n)
	for i := range md {
		md[i] = fmt.Sprintf(`batch-%d`, i)
	}

	res, err := idx.Insert(ctx, envector.InsertRequest{
		Vectors:  vecs,
		Metadata: md,
	})
	if err != nil {
		t.Fatalf("Insert(n=%d): %v", n, err)
	}
	if len(res.ItemIDs) < n {
		t.Fatalf("ItemIDs count: got %d, want >= %d (logical vectors)", len(res.ItemIDs), n)
	}
	t.Logf("server allocated %d ItemIDs for %d logical vectors (slot-aligned)", len(res.ItemIDs), n)
}
