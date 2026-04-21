//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	envector "github.com/CryptoLabInc/envector-go-sdk"
)

// runID namespaces every server-side resource a single `go test` invocation
// creates on the cloud. Anything that escapes t.Cleanup (panics, SIGKILL)
// is still reachable to the TestMain sweeper via this prefix, and parallel
// CI runs stay disjoint.
//
// Both key IDs and index names live under aggressive length caps on the
// server side (seen: varchar(20) for key_id). Layout is `{runID}{kind}{n}`
// with no separators — `kind` is literal 'k' / 'i', which sit outside the
// hex alphabet so a prefix match against runID can never be confused with
// a different run's runID even without delimiters.
//   - runID  = "e" + shortHex(2) → 5 chars (e.g. "ea3f2")
//   - kind   = 1 char
//   - n      = hex(atomic counter) → 1–2 chars for a normal suite run
// Total: 7–8 chars. Well under 20.
var (
	runID   = "e" + shortHex(2)
	uniqSeq atomic.Uint64
)

const (
	envAddr     = "ENVECTOR_ADDR"
	envToken    = "ENVECTOR_TOKEN"
	envInsecure = "ENVECTOR_INSECURE"

	cleanupTimeout = 30 * time.Second
	sweepTimeout   = 60 * time.Second
)

func shortHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func uniqueName(kind string) string {
	return fmt.Sprintf("%s%s%x", runID, kind, uniqSeq.Add(1))
}

func skipIfNoEndpoint(t *testing.T) (addr, token string, insecure bool) {
	t.Helper()
	addr = os.Getenv(envAddr)
	if addr == "" {
		t.Skipf("%s not set; skipping e2e test", envAddr)
	}
	token = os.Getenv(envToken)
	insecure = os.Getenv(envInsecure) == "1"
	return
}

func clientOptionsFromEnv(addr, token string, insecure bool) []envector.ClientOption {
	opts := []envector.ClientOption{envector.WithAddress(addr)}
	if token != "" {
		opts = append(opts, envector.WithAccessToken(token))
	}
	if insecure {
		opts = append(opts, envector.WithInsecure())
	}
	return opts
}

func newTestClient(t *testing.T) *envector.Client {
	t.Helper()
	addr, token, insecure := skipIfNoEndpoint(t)
	client, err := envector.NewClient(clientOptionsFromEnv(addr, token, insecure)...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Logf("client.Close: %v", err)
		}
	})
	return client
}

func newTestKeys(t *testing.T, dim int, preset envector.Preset, evalMode envector.EvalMode) *envector.Keys {
	t.Helper()
	dir := t.TempDir()
	keyID := uniqueName("k")
	opts := []envector.KeysOption{
		envector.WithKeyPath(dir),
		envector.WithKeyID(keyID),
		envector.WithKeyPreset(preset),
		envector.WithKeyEvalMode(evalMode),
		envector.WithKeyDim(dim),
	}
	if err := envector.GenerateKeys(opts...); err != nil {
		t.Fatalf("GenerateKeys(%q, dim=%d): %v", keyID, dim, err)
	}
	keys, err := envector.OpenKeysFromFile(opts...)
	if err != nil {
		t.Fatalf("OpenKeysFromFile(%q): %v", keyID, err)
	}
	t.Cleanup(func() {
		if err := keys.Close(); err != nil {
			t.Logf("keys.Close(%q): %v", keyID, err)
		}
	})
	return keys
}

// activateKeysWithCleanup calls ActivateKeys and registers a best-effort
// DeleteKeys cleanup. Split out so tests that exercise the key lifecycle
// without an index (Test C) can reuse the same teardown discipline as
// tests that layer an index on top (Tests D/E/F via newTestIndex).
func activateKeysWithCleanup(t *testing.T, ctx context.Context, client *envector.Client, keys *envector.Keys) {
	t.Helper()
	if err := client.ActivateKeys(ctx, keys); err != nil {
		t.Fatalf("ActivateKeys(%q): %v", keys.ID(), err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if err := client.DeleteKeys(cctx, keys.ID()); err != nil {
			t.Logf("DeleteKeys(%q): %v", keys.ID(), err)
		}
	})
}

// newTestIndex activates keys on the server, opens (creating if absent) a
// unique-named index bound to those keys, and registers cleanup in the
// order Drop → DeleteKeys (index first so the key can't be pinned by a
// lingering index reference). Cleanup contexts are fresh — t.Context()
// is already canceled by the time cleanups run.
func newTestIndex(t *testing.T, ctx context.Context, client *envector.Client, keys *envector.Keys) *envector.Index {
	t.Helper()
	activateKeysWithCleanup(t, ctx, client, keys)
	name := uniqueName("i")
	idx, err := client.Index(ctx,
		envector.WithIndexName(name),
		envector.WithIndexKeys(keys),
	)
	if err != nil {
		t.Fatalf("Client.Index(%q): %v", name, err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if err := idx.Drop(cctx); err != nil {
			t.Logf("idx.Drop(%q): %v", name, err)
		}
	})
	return idx
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// sampleVectors returns n test vectors of length dim, laid out as the
// standard basis: vectors[i][i] = 1.0, other coordinates zero. Pairwise
// inner product is δ_ij, which makes F1's score-correctness assertion
// (one slot ≈ 1, rest ≈ 0) trivial to state. n must not exceed dim.
func sampleVectors(n, dim int) [][]float32 {
	if n > dim {
		panic(fmt.Sprintf("sampleVectors: n=%d exceeds dim=%d (basis would not be linearly independent)", n, dim))
	}
	out := make([][]float32, n)
	for i := 0; i < n; i++ {
		v := make([]float32, dim)
		v[i] = 1.0
		out[i] = v
	}
	return out
}

// approxEqual compares two equal-length float64 slots within an absolute
// epsilon. eps is caller-chosen; empirically ~1e-2 is safe at dim=128 /
// PresetIP0 / EvalModeRMP — larger dims or different presets may need a
// looser bound.
func approxEqual(t *testing.T, got, want []float64, eps float64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		if d := math.Abs(got[i] - want[i]); d > eps {
			t.Fatalf("index %d: got %.6f, want %.6f, diff %.6f > eps %.6f",
				i, got[i], want[i], d, eps)
		}
	}
}

// TestMain runs the suite, then sweeps any runID-prefixed resources that
// escaped t.Cleanup (panics, `kill -9`, t.Skip after partial setup). The
// sweeper is best-effort: failures are logged, never converted into exit
// codes — that would mask the actual test results from m.Run.
func TestMain(m *testing.M) {
	code := m.Run()
	sweep()
	os.Exit(code)
}

func sweep() {
	addr := os.Getenv(envAddr)
	if addr == "" {
		return
	}
	token := os.Getenv(envToken)
	insecure := os.Getenv(envInsecure) == "1"
	client, err := envector.NewClient(clientOptionsFromEnv(addr, token, insecure)...)
	if err != nil {
		log.Printf("sweeper: NewClient: %v", err)
		return
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), sweepTimeout)
	defer cancel()

	var idxResidual, keyResidual int
	if names, err := client.GetIndexList(ctx); err == nil {
		for _, n := range names {
			if !strings.HasPrefix(n, runID) {
				continue
			}
			idx, err := client.Index(ctx, envector.WithIndexName(n))
			if err != nil {
				log.Printf("sweeper: open index %q: %v", n, err)
				idxResidual++
				continue
			}
			if err := idx.Drop(ctx); err != nil {
				log.Printf("sweeper: Drop(%q): %v", n, err)
				idxResidual++
			}
		}
	} else {
		log.Printf("sweeper: GetIndexList: %v", err)
	}

	if ids, err := client.GetKeysList(ctx); err == nil {
		for _, id := range ids {
			if !strings.HasPrefix(id, runID) {
				continue
			}
			if err := client.DeleteKeys(ctx, id); err != nil {
				log.Printf("sweeper: DeleteKeys(%q): %v", id, err)
				keyResidual++
			}
		}
	} else {
		log.Printf("sweeper: GetKeysList: %v", err)
	}

	if idxResidual+keyResidual > 0 {
		log.Printf("sweeper: %d indexes / %d keys still present under prefix %q; manual cleanup needed",
			idxResidual, keyResidual, runID)
	} else {
		log.Printf("sweeper: 0 residuals under prefix %q", runID)
	}
}
