//go:build e2e

package e2e

import (
	"context"
	"testing"

	envector "github.com/CryptoLabInc/envector-go-sdk"
)

// TestKeys_ActivateListDelete exercises the register/load/unload/delete
// sequence on the real backend: after ActivateKeys the key appears in
// GetKeysList, after DeleteKeys it does not. The bufconn fake covers the
// sequencing logic client-side — what this test adds is verifying the
// server persists state across RPCs as the SDK expects.
func TestKeys_ActivateListDelete(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()
	keys := newTestKeys(t, 128, envector.PresetIP0, envector.EvalModeRMP)

	activateKeysWithCleanup(t, ctx, client, keys)

	list, err := client.GetKeysList(ctx)
	if err != nil {
		t.Fatalf("GetKeysList after Activate: %v", err)
	}
	if !contains(list, keys.ID()) {
		t.Fatalf("key %q missing from list after Activate; got %v", keys.ID(), list)
	}

	if err := client.DeleteKeys(ctx, keys.ID()); err != nil {
		t.Fatalf("DeleteKeys: %v", err)
	}

	list2, err := client.GetKeysList(ctx)
	if err != nil {
		t.Fatalf("GetKeysList after Delete: %v", err)
	}
	if contains(list2, keys.ID()) {
		t.Fatalf("key %q still in list after Delete; got %v", keys.ID(), list2)
	}
}
