//go:build e2e

package e2e

import (
	"context"
	"testing"
)

// TestConnectivity_GetKeysList is the canary: successful TLS handshake,
// bearer-token auth accepted, one trivial RPC round-trip. Every downstream
// test depends on this path; if it fails, the rest is noise.
func TestConnectivity_GetKeysList(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()
	if _, err := client.GetKeysList(ctx); err != nil {
		t.Fatalf("GetKeysList on fresh client: %v", err)
	}
}
