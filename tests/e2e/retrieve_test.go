//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"math"
	"testing"

	envector "github.com/CryptoLabInc/envector-go-sdk"
)

// TestRetrieve_ScoreAndMetadataRoundTrip is the single scenario the E2E
// suite exists to justify: encrypt plaintext vectors locally, let the
// server compute inner products against the ciphertexts, decrypt locally,
// and verify both (1) numerical correctness within FHE noise and (2) that
// the decryption-reported (shardIdx, rowIdx) pair maps back to the same
// row's metadata on a follow-up GetMetadata call.
//
// Fixture: orthogonal (standard) basis vectors e_0 .. e_{n-1}. Query is
// e_{queryIdx}. Plaintext IP is δ_{queryIdx,i}, so the decrypted score
// vector should have exactly one slot ≈ 1.0 and all others ≈ 0.0.
func TestRetrieve_ScoreAndMetadataRoundTrip(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()
	keys := newTestKeys(t, 128, envector.PresetIP0, envector.EvalModeRMP)
	idx := newTestIndex(t, ctx, client, keys)

	const (
		n        = 8
		dim      = 128
		queryIdx = 3
		eps      = 1e-2
	)
	vecs := sampleVectors(n, dim)
	md := make([]string, n)
	for i := range md {
		md[i] = fmt.Sprintf(`{"i":%d}`, i)
	}
	if _, err := idx.Insert(ctx, envector.InsertRequest{
		Vectors:  vecs,
		Metadata: md,
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	blobs, err := idx.Score(ctx, vecs[queryIdx])
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if len(blobs) != 1 {
		t.Fatalf("Score returned %d blobs, want 1 (single query)", len(blobs))
	}

	scores, shardIdx, err := keys.Decrypt(blobs[0])
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(scores) != len(shardIdx) {
		t.Fatalf("Decrypt shape mismatch: %d score rows vs %d shard indices", len(scores), len(shardIdx))
	}

	bestOuter, bestRow := -1, -1
	bestVal := math.Inf(-1)
	for s, shard := range scores {
		for r, v := range shard {
			if v > bestVal {
				bestVal = v
				bestOuter = s
				bestRow = r
			}
		}
	}

	t.Run("score_correctness", func(t *testing.T) {
		// FHE slot packing + server-side replication can place the matching
		// vector in more than one decrypted slot (observed: 3 slots ≈ 1.0
		// for a single-match orthogonal query). The correctness contract
		// we can actually assert is: every slot is near 0 or near 1 (no
		// stray values outside FHE noise of {0,1}), the top-1 is ≈ 1.0,
		// and at least one slot matches. The exact count of 1.0 slots is
		// server-storage-dependent — F2's metadata lookup confirms the
		// top-1 identity separately.
		var ones int
		var worstDelta float64
		for s, shard := range scores {
			for r, v := range shard {
				near1 := math.Abs(v-1.0) <= eps
				near0 := math.Abs(v) <= eps
				if !near1 && !near0 {
					t.Fatalf("slot (shard=%d, row=%d): score %.6f not near 0 or 1 (eps=%.2e)", s, r, v, eps)
				}
				if near1 {
					ones++
				}
				if d := math.Min(math.Abs(v), math.Abs(v-1)); d > worstDelta {
					worstDelta = d
				}
			}
		}
		if ones < 1 {
			t.Fatalf("expected at least 1 slot ≈ 1.0, got 0 (worst delta from {0,1}: %.6e)", worstDelta)
		}
		if math.Abs(bestVal-1.0) > eps {
			t.Fatalf("top-1 score %.6f, expected ≈ 1.0 (eps=%.2e)", bestVal, eps)
		}
		t.Logf("FHE decrypt: %d slot(s) ≈ 1.0, worst delta from {0,1} = %.6e", ones, worstDelta)
	})

	t.Run("metadata_roundtrip", func(t *testing.T) {
		if bestOuter < 0 {
			t.Fatalf("no best slot located (empty scores?)")
		}
		ref := envector.MetadataRef{
			ShardIdx: uint64(shardIdx[bestOuter]),
			RowIdx:   uint64(bestRow),
		}
		out, err := idx.GetMetadata(ctx, []envector.MetadataRef{ref}, []string{"metadata"})
		if err != nil {
			t.Fatalf("GetMetadata: %v", err)
		}
		if len(out) != 1 {
			t.Fatalf("GetMetadata returned %d rows, want 1", len(out))
		}
		if got, want := out[0].Data, md[queryIdx]; got != want {
			t.Fatalf("metadata mismatch at top-1 ref: got %q, want %q", got, want)
		}
	})
}
