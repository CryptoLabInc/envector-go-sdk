package envector

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	es2pb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2"
	es2epb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2e"
)

func TestIndex_Score_MergesStreamByID(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.indexList = []string{"rune"}
	idx, _ := c.Index(context.Background(), WithIndexName("rune"))

	// Three server responses, two response IDs interleaved.
	fake.ipResponses = []*es2epb.InnerProductResponse{
		{Header: okHeader(), CtxtScore: []*es2pb.CiphertextScore{
			{Id: "q-1", ShardIdx: []uint64{1}, CtxtScore: []*es2pb.HEaaNCiphertext{{Degree: 2, Data: []byte("aa")}}},
			{Id: "q-2", ShardIdx: []uint64{10}, CtxtScore: []*es2pb.HEaaNCiphertext{{Degree: 2, Data: []byte("bb")}}},
		}},
		{Header: okHeader(), CtxtScore: []*es2pb.CiphertextScore{
			{Id: "q-1", ShardIdx: []uint64{2, 3}, CtxtScore: []*es2pb.HEaaNCiphertext{{Degree: 2, Data: []byte("cc")}}},
		}},
		{Header: okHeader(), CtxtScore: []*es2pb.CiphertextScore{
			{Id: "q-2", ShardIdx: []uint64{11}, CtxtScore: []*es2pb.HEaaNCiphertext{{Degree: 2, Data: []byte("dd")}}},
		}},
	}

	blobs, err := idx.Score(context.Background(), []float32{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if len(blobs) != 2 {
		t.Fatalf("blobs = %d, want 2 (one per response ID)", len(blobs))
	}

	// First blob should be q-1 (seen first) and carry merged ShardIdx [1,2,3].
	var first es2pb.CiphertextScore
	if err := proto.Unmarshal(blobs[0], &first); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if first.GetId() != "q-1" {
		t.Errorf("id[0] = %q, want q-1", first.GetId())
	}
	if got := first.GetShardIdx(); len(got) != 3 || got[0] != 1 || got[2] != 3 {
		t.Errorf("merged shards = %v", got)
	}
	if len(first.GetCtxtScore()) != 2 {
		t.Errorf("ctxt count = %d, want 2", len(first.GetCtxtScore()))
	}
}

func TestIndex_Score_QueryCarriesIndexName(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.indexList = []string{"rune"}
	idx, _ := c.Index(context.Background(), WithIndexName("rune"))

	if _, err := idx.Score(context.Background(), []float32{1, 2}); err != nil {
		t.Fatalf("Score: %v", err)
	}
	if fake.innerProductReq.GetIndexName() != "rune" {
		t.Errorf("IndexName = %q", fake.innerProductReq.GetIndexName())
	}
	if len(fake.innerProductReq.GetQueryVector()) != 1 {
		t.Fatalf("QueryVector = %d, want 1", len(fake.innerProductReq.GetQueryVector()))
	}
	if fake.innerProductReq.GetQueryVector()[0].GetPlainVector().GetDim() != 2 {
		t.Errorf("Dim = %d", fake.innerProductReq.GetQueryVector()[0].GetPlainVector().GetDim())
	}
}
