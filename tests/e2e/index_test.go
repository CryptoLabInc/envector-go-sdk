//go:build e2e

package e2e

import (
	"context"
	"testing"

	envector "github.com/CryptoLabInc/envector-go-sdk"
)

// TestIndex_CreateListDrop verifies index create/drop persists on the real
// backend. Dim is sourced from Keys.Dim() (passed via WithIndexKeys); the
// Index never carries its own dim, so this also cross-checks that the
// keys-derived dim reaches the server correctly.
func TestIndex_CreateListDrop(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()
	keys := newTestKeys(t, 128, envector.PresetIP0, envector.EvalModeRMP)
	idx := newTestIndex(t, ctx, client, keys)

	list, err := client.GetIndexList(ctx)
	if err != nil {
		t.Fatalf("GetIndexList: %v", err)
	}
	if !contains(list, idx.Name()) {
		t.Fatalf("index %q missing from list; got %v", idx.Name(), list)
	}

	if err := idx.Drop(ctx); err != nil {
		t.Fatalf("Drop: %v", err)
	}

	list2, err := client.GetIndexList(ctx)
	if err != nil {
		t.Fatalf("GetIndexList after Drop: %v", err)
	}
	if contains(list2, idx.Name()) {
		t.Fatalf("index %q still in list after Drop", idx.Name())
	}
}
