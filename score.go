package envector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	es2pb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2"
	es2epb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2e"
)

func (i *Index) Score(ctx context.Context, query []float32) ([][]byte, error) {
	if i.client.conn == nil {
		return nil, ErrClientClosed
	}
	queryID := randomQueryID()
	req := &es2epb.InnerProductRequest{
		Header:    &es2pb.RequestHeader{Type: es2pb.MessageType_InnerProduct},
		IndexName: i.name,
		QueryVector: []*es2pb.DataType{{
			PlainVector: &es2pb.Vector{
				Id:   queryID,
				Dim:  uint64(len(query)),
				Data: query,
			},
		}},
	}

	stream, err := i.client.stub.InnerProduct(i.client.authCtx(ctx), req)
	if err != nil {
		return nil, fmt.Errorf("envector: inner_product: %w", err)
	}

	shards := map[string][]uint64{}
	ctxt := map[string][]*es2pb.HEaaNCiphertext{}
	order := []string{}

	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("envector: inner_product recv: %w", err)
		}
		if err := checkHeader("inner_product", resp.GetHeader()); err != nil {
			return nil, err
		}
		for _, cs := range resp.GetCtxtScore() {
			id := cs.GetId()
			if _, seen := shards[id]; !seen {
				order = append(order, id)
			}
			shards[id] = append(shards[id], cs.GetShardIdx()...)
			ctxt[id] = append(ctxt[id], cs.GetCtxtScore()...)
		}
	}

	out := make([][]byte, 0, len(order))
	for _, id := range order {
		final := &es2pb.CiphertextScore{
			Id:        id,
			ShardIdx:  shards[id],
			CtxtScore: ctxt[id],
		}
		buf, err := proto.Marshal(final)
		if err != nil {
			return nil, fmt.Errorf("envector: marshal CiphertextScore: %w", err)
		}
		out = append(out, buf)
	}
	return out, nil
}

func randomQueryID() string {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "id-00000"
	}
	return "id-" + hex.EncodeToString(b[:])
}
