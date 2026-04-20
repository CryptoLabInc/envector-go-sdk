package envector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"reflect"
	"testing"
)

// openTestKeys produces a *Keys backed by the mock crypto provider, suitable
// for exercising Client-side RPC paths. The EvalKey bytes are set to a fixed
// 2.5 MiB payload so that RegisterKeys must emit three 1 MiB frames.
func openTestKeys(t *testing.T) *Keys {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keys")
	if err := GenerateKeys(baseKeyOpts(dir)...); err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	keys, err := OpenKeysFromFile(baseKeyOpts(dir)...)
	if err != nil {
		t.Fatalf("OpenKeysFromFile: %v", err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	keys.evalKeyBytes = bytes.Repeat([]byte{0xA5}, keyUploadChunkSize*2+keyUploadChunkSize/2)
	return keys
}

func TestGetKeysList_ReturnsServerList(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.keyList = []string{"a", "b"}
	got, err := c.GetKeysList(context.Background())
	if err != nil {
		t.Fatalf("GetKeysList: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("got %v, want [a b]", got)
	}
	if fake.getKeyListCalls != 1 {
		t.Errorf("calls = %d, want 1", fake.getKeyListCalls)
	}
}

func TestRegisterKeys_ChunksAt1MiBWithSHA256(t *testing.T) {
	c, fake := newFakeClient(t)
	keys := openTestKeys(t)

	if err := c.RegisterKeys(context.Background(), keys); err != nil {
		t.Fatalf("RegisterKeys: %v", err)
	}

	if len(fake.registerKeyChunks) != 3 {
		t.Fatalf("chunks = %d, want 3", len(fake.registerKeyChunks))
	}
	if len(fake.registerKeyChunks[0]) != keyUploadChunkSize {
		t.Errorf("chunk 0 size = %d, want %d", len(fake.registerKeyChunks[0]), keyUploadChunkSize)
	}
	if len(fake.registerKeyChunks[2]) != keyUploadChunkSize/2 {
		t.Errorf("chunk 2 size = %d, want %d (tail)", len(fake.registerKeyChunks[2]), keyUploadChunkSize/2)
	}

	want := sha256.Sum256(keys.evalKeyBytes)
	if got := fake.registerKeyInfo.GetSha256Sum(); got != hex.EncodeToString(want[:]) {
		t.Errorf("sha256 mismatch: got %q want %q", got, hex.EncodeToString(want[:]))
	}
	if fake.registerKeyInfo.GetKeyId() != keys.id {
		t.Errorf("KeyId = %q, want %q", fake.registerKeyInfo.GetKeyId(), keys.id)
	}
	if fake.registerKeyInfo.GetType() != "EvalKey" {
		t.Errorf("Type = %q, want EvalKey", fake.registerKeyInfo.GetType())
	}
}

func TestLoadUnloadDeleteKeys(t *testing.T) {
	c, fake := newFakeClient(t)

	if err := c.LoadKeys(context.Background(), "k1"); err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	if err := c.UnloadKeys(context.Background(), "k2"); err != nil {
		t.Fatalf("UnloadKeys: %v", err)
	}
	if err := c.DeleteKeys(context.Background(), "k3"); err != nil {
		t.Fatalf("DeleteKeys: %v", err)
	}
	if !reflect.DeepEqual(fake.loadKeyCalls, []string{"k1"}) {
		t.Errorf("loadKeyCalls = %v", fake.loadKeyCalls)
	}
	if !reflect.DeepEqual(fake.unloadKeyCalls, []string{"k2"}) {
		t.Errorf("unloadKeyCalls = %v", fake.unloadKeyCalls)
	}
	if !reflect.DeepEqual(fake.deleteKeyCalls, []string{"k3"}) {
		t.Errorf("deleteKeyCalls = %v", fake.deleteKeyCalls)
	}
}

func TestActivateKeys_NewKey_Register_Load_NoUnloads(t *testing.T) {
	c, fake := newFakeClient(t)
	keys := openTestKeys(t) // id = "test-key"
	// Empty server state: no existing keys.

	if err := c.ActivateKeys(context.Background(), keys); err != nil {
		t.Fatalf("ActivateKeys: %v", err)
	}

	if len(fake.registerKeyChunks) == 0 {
		t.Error("expected RegisterKeys streaming")
	}
	if len(fake.unloadKeyCalls) != 0 {
		t.Errorf("unexpected unloads: %v", fake.unloadKeyCalls)
	}
	if !reflect.DeepEqual(fake.loadKeyCalls, []string{keys.id}) {
		t.Errorf("loadKeyCalls = %v, want [%s]", fake.loadKeyCalls, keys.id)
	}
	if keys.activated != c {
		t.Error("keys.activated not set to client")
	}
}

func TestActivateKeys_SkipRegister_UnloadOthers(t *testing.T) {
	c, fake := newFakeClient(t)
	keys := openTestKeys(t)
	fake.keyList = []string{"stale-a", keys.id, "stale-b"}

	if err := c.ActivateKeys(context.Background(), keys); err != nil {
		t.Fatalf("ActivateKeys: %v", err)
	}
	if len(fake.registerKeyChunks) != 0 {
		t.Error("RegisterKeys should be skipped when key already present")
	}
	wantUnload := map[string]bool{"stale-a": true, "stale-b": true}
	for _, k := range fake.unloadKeyCalls {
		delete(wantUnload, k)
	}
	if len(wantUnload) != 0 {
		t.Errorf("unloads missed: %v (got %v)", wantUnload, fake.unloadKeyCalls)
	}
	if !reflect.DeepEqual(fake.loadKeyCalls, []string{keys.id}) {
		t.Errorf("loadKeyCalls = %v", fake.loadKeyCalls)
	}
}

func TestActivateKeys_AcrossClients_RejectsSecond(t *testing.T) {
	c1, _ := newFakeClient(t)
	c2, _ := newFakeClient(t)
	keys := openTestKeys(t)

	if err := c1.ActivateKeys(context.Background(), keys); err != nil {
		t.Fatalf("ActivateKeys c1: %v", err)
	}
	err := c2.ActivateKeys(context.Background(), keys)
	if err == nil || err != ErrKeysAlreadyActivated {
		t.Errorf("second activate: got %v, want ErrKeysAlreadyActivated", err)
	}
}

func TestClient_KeyRPCs_AfterCloseReturnErrClientClosed(t *testing.T) {
	c, _ := newFakeClient(t)
	_ = c.Close()

	ctx := context.Background()
	if err := c.LoadKeys(ctx, "x"); err != ErrClientClosed {
		t.Errorf("LoadKeys: %v", err)
	}
	if err := c.UnloadKeys(ctx, "x"); err != ErrClientClosed {
		t.Errorf("UnloadKeys: %v", err)
	}
	if err := c.DeleteKeys(ctx, "x"); err != ErrClientClosed {
		t.Errorf("DeleteKeys: %v", err)
	}
}
